// SPDX-License-Identifier: GPL-2.0

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/err.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/kobject.h>
#include <linux/kthread.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/pid.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/uaccess.h>

#include "taskmonitor.h"

struct taskmonitor {
	struct mutex lock;
	struct pid *pid;
	struct mutex thread_lock;
	struct task_struct *thread;
};

struct taskmonitor_sample {
	pid_t pid;
	u64 utime;
	u64 stime;
};

static void taskmonitor_unset_pid(struct taskmonitor *tmon)
{
	if (tmon->pid == NULL)
		return;

	put_pid(tmon->pid);
	tmon->pid = NULL;
}

static int taskmonitor_sample(struct taskmonitor *tmon, struct taskmonitor_sample *smp)
{
	struct task_struct *task = get_pid_task(tmon->pid, PIDTYPE_PID);
	if (IS_ERR(task))
		return PTR_ERR(task);

	if (!task || !pid_alive(task))
		return 0;

	*smp = (struct taskmonitor_sample) {
		.pid = pid_nr(tmon->pid),
		.utime = task->utime,
		.stime = task->stime,
	};

	put_task_struct(task);

	return 1;
}

static void taskmonitor_lock(struct taskmonitor *tmon)
{
	mutex_lock(&tmon->lock);
}

static void taskmonitor_unlock(struct taskmonitor *tmon)
{
	mutex_unlock(&tmon->lock);
}

// alias monitor_fn
static int taskmonitor_threadfn(void *arg)
{
	int err;
	struct taskmonitor *tmon = arg;
	struct taskmonitor_sample smp;

	while (!kthread_should_stop()) {
		taskmonitor_lock(tmon);

		err = taskmonitor_sample(tmon, &smp);
		if (err <= 0) {
			taskmonitor_unset_pid(tmon);
			taskmonitor_unlock(tmon);
			return err;
		}

		taskmonitor_unlock(tmon);

		printk(KERN_INFO "pid %d usr %llu sys %llu\n", smp.pid, smp.utime, smp.stime);

		schedule_timeout_uninterruptible(HZ);
	}

	return 0;
}

static int taskmonitor_start_unlocked(struct taskmonitor *tmon)
{
	struct task_struct *thread;

	if (tmon->thread)
		return 0;

	thread = kthread_create(taskmonitor_threadfn, tmon, "taskmonitor(%d)", pid_nr(tmon->pid));
	if (IS_ERR(thread))
		return PTR_ERR(thread);

	get_task_struct(thread);
	wake_up_process(thread);

	tmon->thread = thread;

	return 0;
}

static int taskmonitor_start(struct taskmonitor *tmon)
{
	mutex_lock(&tmon->thread_lock);
	int ret = taskmonitor_start_unlocked(tmon);
	mutex_unlock(&tmon->thread_lock);
	return ret;
}

static void taskmonitor_stop_unlocked(struct taskmonitor *tmon)
{
	if (!tmon->thread)
		return;

	kthread_stop(tmon->thread);
	put_task_struct(tmon->thread);

	tmon->thread = NULL;
}

static void taskmonitor_stop(struct taskmonitor *tmon)
{
	mutex_lock(&tmon->thread_lock);
	taskmonitor_stop_unlocked(tmon);
	mutex_unlock(&tmon->thread_lock);
}

static int taskmonitor_restart(struct taskmonitor *tmon)
{
	mutex_lock(&tmon->thread_lock);
	taskmonitor_stop_unlocked(tmon);
	int ret = taskmonitor_start_unlocked(tmon);
	mutex_unlock(&tmon->thread_lock);
	return ret;
}

// alias monitor_pid
static int taskmonitor_set_pid(struct taskmonitor *tmon, pid_t nr)
{
	struct pid *pid;

	taskmonitor_unset_pid(tmon);

	pid = find_get_pid(nr);
	if (IS_ERR(pid))
		return PTR_ERR(pid);

	if (!pid)
		return -EINVAL;

	tmon->pid = pid;

	taskmonitor_restart(tmon);

	return 0;
}

// global private taskmonitor instance
static struct taskmonitor *taskmonitor_private;

static long taskmonitor_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	int err;
	pid_t pid;
	void __user *ptr = (void __user *)arg;
	struct taskmonitor *tmon = taskmonitor_private;
	struct taskmonitor_sample smp;

	switch (cmd) {
	case TM_GET:
		err = taskmonitor_sample(tmon, &smp);
		if (err <= 0)
			return err ? err : -EINVAL;

		struct task_sample usmp = {
			.utime = smp.utime,
			.stime = smp.stime,
		};

		err = copy_to_user(ptr, &usmp, sizeof(usmp));
		if (err)
			return err;

		return 0;

	case TM_START:
		err = taskmonitor_start(tmon);
		if (err)
			return err;

		return 0;

	case TM_STOP:
		taskmonitor_stop(tmon);

		return 0;

	case TM_PID:
		err = copy_from_user(&pid, ptr, sizeof(pid));
		if (err)
			return err;

		if (pid < 0) {
			if (!tmon->pid)
				return -EINVAL;

			pid = pid_nr(tmon->pid);
			err = copy_to_user(ptr, &pid, sizeof(pid));
			if (err)
				return err;
		} else {
			err = taskmonitor_set_pid(tmon, pid);
			if (err)
				return err;
		}

		return 0;

	default:
		return -ENOTTY;
	}
}

static int taskmonitor_major;
static const struct file_operations taskmonitor_fops = {
	.unlocked_ioctl = taskmonitor_ioctl,
};

static ssize_t taskmonitor_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf,
				      size_t count)
{
	int err;
	struct taskmonitor *tmon = taskmonitor_private;

	if (sysfs_streq(buf, "start")) {
		err = taskmonitor_start(tmon);
		if (err)
			return err;

		return count;
	}

	if (sysfs_streq(buf, "stop")) {
		taskmonitor_stop(tmon);
		return count;
	}

	return -EINVAL;
}

static ssize_t taskmonitor_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	int err;
	struct taskmonitor *tmon = taskmonitor_private;
	struct taskmonitor_sample smp;

	taskmonitor_lock(tmon);

	err = taskmonitor_sample(tmon, &smp);
	if (err <= 0) {
		taskmonitor_unset_pid(tmon);
		taskmonitor_unlock(tmon);
		return err;
	}

	taskmonitor_unlock(tmon);

	return sysfs_emit(buf, "pid %d usr %llu sys %llu\n", smp.pid, smp.utime, smp.stime);
}

static const struct kobj_attribute taskmonitor_attr = __ATTR_RW(taskmonitor);

static pid_t default_target = -1;
module_param_named(target, default_target, int, 0644);

static int __init taskmonitor_init(void)
{
	int err;
	struct taskmonitor *tmon;

	tmon = kzalloc(sizeof(struct taskmonitor), GFP_KERNEL);
	if (IS_ERR(tmon)) {
		err = PTR_ERR(tmon);
		goto err_kzalloc;
	}

	mutex_init(&tmon->lock);

	taskmonitor_private = tmon;

	err = taskmonitor_set_pid(tmon, default_target);
	if (err)
		goto err_monitor;

	err = taskmonitor_start_unlocked(tmon);
	if (err)
		goto err_monitor;

	err = sysfs_create_file(kernel_kobj, &taskmonitor_attr.attr);
	if (err)
		goto err_monitor;

	taskmonitor_major = register_chrdev(0, "taskmonitor", &taskmonitor_fops);
	if (taskmonitor_major < 0) {
		err = taskmonitor_major;
		goto err_chrdev;
	}

	return 0;

err_chrdev:
	sysfs_remove_file(kernel_kobj, &taskmonitor_attr.attr);
err_monitor:
	taskmonitor_stop_unlocked(tmon);
	taskmonitor_unset_pid(tmon);
	mutex_destroy(&tmon->lock);
	kfree(tmon);
err_kzalloc:
	return err;
}
module_init(taskmonitor_init)

static void __exit taskmonitor_exit(void)
{
	struct taskmonitor *tmon = taskmonitor_private;

	unregister_chrdev(taskmonitor_major, "taskmonitor");
	sysfs_remove_file(kernel_kobj, &taskmonitor_attr.attr);
	taskmonitor_stop_unlocked(tmon);
	taskmonitor_unset_pid(tmon);
	mutex_destroy(&tmon->lock);
	kfree(tmon);
}
module_exit(taskmonitor_exit)

MODULE_AUTHOR("Philipp Jungkamp <philipp.jungkamp@rwth-aachen.de>");
MODULE_DESCRIPTION("Monitor a task by pid");
MODULE_LICENSE("GPL");
