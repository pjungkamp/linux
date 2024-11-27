// SPDX-License-Identifier: GPL-2.0

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/err.h>
#include <linux/kernel.h>
#include <linux/kobject.h>
#include <linux/kthread.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/pid.h>
#include <linux/sched.h>
#include <linux/slab.h>

struct taskmonitor {
	struct mutex lock;
	struct pid *pid;
	struct task_struct *thread;
};

struct taskmonitor_sample {
	pid_t pid;
	u64 utime;
	u64 stime;
};

static void taskmonitor_unset_pid(struct taskmonitor *tmon)
{
	if (!tmon->pid)
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

static void taskmonitor_stop(struct taskmonitor *tmon)
{
	if (!tmon->thread)
		return;

	kthread_stop(tmon->thread);

	tmon->thread = NULL;
}

static int taskmonitor_start(struct taskmonitor *tmon)
{
	struct task_struct *thread;

	if (tmon->thread)
		return 0;

	thread = kthread_run(taskmonitor_threadfn, tmon, "taskmonitor(%d)", pid_nr(tmon->pid));
	if (IS_ERR(thread))
		return PTR_ERR(thread);

	tmon->thread = thread;

	return 0;
}

static int taskmonitor_restart(struct taskmonitor *tmon)
{
	if (!tmon->thread)
		return 0;

	taskmonitor_stop(tmon);
	return taskmonitor_start(tmon);
}

// alias monitor_pid
static int taskmonitor_set_pid(struct taskmonitor *tmon, pid_t nr)
{
	struct pid *pid;

	if (tmon->pid)
		taskmonitor_unset_pid(tmon);

	pid = find_get_pid(nr);
	if (IS_ERR(pid))
		return PTR_ERR(pid);

	if (pid == NULL)
		return -EINVAL;

	tmon->pid = pid;

	taskmonitor_restart(tmon);

	return 0;
}

// global private taskmonitor instance
static struct taskmonitor *taskmonitor_private;

static ssize_t taskmonitor_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf,
				      size_t count)
{
	struct taskmonitor *tmon = taskmonitor_private;

	if (sysfs_streq(buf, "start"))
		taskmonitor_start(tmon);
	else if (sysfs_streq(buf, "stop"))
		taskmonitor_stop(tmon);
	else
		return -EINVAL;

	return count;
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

static struct kobj_attribute taskmonitor_attr = __ATTR_RW(taskmonitor);

static pid_t default_target;
module_param_named(target, default_target, int, 0644);

static int __init taskmonitor_init(void)
{
	int err;

	taskmonitor_private = kzalloc(sizeof(struct taskmonitor), GFP_KERNEL);
	if (IS_ERR(taskmonitor_private)) {
		err = PTR_ERR(taskmonitor_private);
		goto err_kzalloc;
	}

	mutex_init(&taskmonitor_private->lock);

	if (default_target != 0) {
		err = taskmonitor_set_pid(taskmonitor_private, default_target);
		if (err)
			goto err_monitor;

		err = taskmonitor_start(taskmonitor_private);
		if (err)
			goto err_monitor;
	}

	err = sysfs_create_file(kernel_kobj, &taskmonitor_attr.attr);
	if (err)
		goto err_monitor;

	return 0;

err_monitor:
	taskmonitor_stop(taskmonitor_private);
	taskmonitor_unset_pid(taskmonitor_private);
	mutex_destroy(&taskmonitor_private->lock);
	kfree(taskmonitor_private);
err_kzalloc:
	return err;
}
module_init(taskmonitor_init)

static void __exit taskmonitor_exit(void)
{
	sysfs_remove_file(kernel_kobj, &taskmonitor_attr.attr);
	taskmonitor_stop(taskmonitor_private);
	taskmonitor_unset_pid(taskmonitor_private);
	mutex_destroy(&taskmonitor_private->lock);
	kfree(taskmonitor_private);
}
module_exit(taskmonitor_exit)

MODULE_AUTHOR("Philipp Jungkamp <philipp.jungkamp@rwth-aachen.de>");
MODULE_DESCRIPTION("Monitor a task by pid");
MODULE_LICENSE("GPL");
