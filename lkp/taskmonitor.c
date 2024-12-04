// SPDX-License-Identifier: GPL-2.0

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/err.h>
#include <linux/fs.h>
#include <linux/gfp_types.h>
#include <linux/kernel.h>
#include <linux/kobject.h>
#include <linux/kthread.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/pid.h>
#include <linux/sched.h>
#include <linux/shrinker.h>
#include <linux/slab.h>
#include <linux/uaccess.h>

#include "taskmonitor.h"

struct taskmonitor {
	struct mutex lock;
	struct pid *pid;
	struct list_head samples;
	unsigned long samples_count;
	struct shrinker samples_shrinker;
	struct kmem_cache *samples_cache;

	struct mutex thread_lock;
	struct task_struct *thread;
};

struct taskmonitor_sample {
	pid_t pid;
	u64 utime;
	u64 stime;
	unsigned long vm_total;
	unsigned long vm_stack;
	unsigned long vm_data;

	struct list_head list;
};

static struct taskmonitor_sample *taskmonitor_sample_new(struct taskmonitor *tmon)
{
	struct taskmonitor_sample *ret = NULL;
	struct task_struct *task;

	task = get_pid_task(tmon->pid, PIDTYPE_PID);
	if (IS_ERR_OR_NULL(task)) {
		ret = ERR_CAST(task);
		goto err_pid_task;
	}

	if (!pid_alive(task))
		goto err_pid_alive;

	ret = kmem_cache_alloc(tmon->samples_cache, GFP_KERNEL);
	if (IS_ERR(ret))
		goto err_pid_alive;

	ret->pid = pid_nr(tmon->pid);
	ret->utime = task->utime;
	ret->stime = task->stime;
	ret->vm_total = task->mm->total_vm;
	ret->vm_stack = task->mm->stack_vm;
	ret->vm_data = task->mm->data_vm;

err_pid_alive:
	put_task_struct(task);
err_pid_task:
	return ret;
}

static void taskmonitor_sample_free(struct taskmonitor *tmon, struct taskmonitor_sample *smp)
{
	kmem_cache_free(tmon->samples_cache, smp);
}

static void taskmonitor_samples_add(struct taskmonitor *tmon, struct taskmonitor_sample *smp)
{
	tmon->samples_count++;
	list_add_tail(&smp->list, &tmon->samples);
}

static void taskmonitor_samples_reset(struct taskmonitor *tmon)
{
	struct taskmonitor_sample *smp, *next;

	tmon->samples_count = 0;
	list_for_each_entry_safe(smp, next, &tmon->samples, list) {
		list_del(&smp->list);
		taskmonitor_sample_free(tmon, smp);
	}
}

static void taskmonitor_unset_pid(struct taskmonitor *tmon)
{
	if (tmon->pid == NULL)
		return;

	put_pid(tmon->pid);
	tmon->pid = NULL;

	taskmonitor_samples_reset(tmon);
}

static bool taskmonitor_trylock(struct taskmonitor *tmon)
{
	return mutex_trylock(&tmon->lock);
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
	struct taskmonitor *tmon = arg;
	struct taskmonitor_sample *smp;

	while (!kthread_should_stop()) {
		taskmonitor_lock(tmon);

		smp = taskmonitor_sample_new(tmon);
		if (IS_ERR_OR_NULL(smp)) {
			taskmonitor_unset_pid(tmon);
			taskmonitor_unlock(tmon);
			return PTR_ERR(smp);
		}

		taskmonitor_samples_add(tmon, smp);

		taskmonitor_unlock(tmon);

		schedule_timeout_uninterruptible(HZ);
	}

	return 0;
}

static int taskmonitor_start_unlocked(struct taskmonitor *tmon)
{
	struct task_struct *thread;

	if (tmon->thread)
		return 0;

	thread = kthread_create(taskmonitor_threadfn, tmon, "tmon/%d", pid_nr(tmon->pid));
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
	int ret = 0;

	mutex_lock(&tmon->thread_lock);

	if (tmon->thread) {
		taskmonitor_stop_unlocked(tmon);
		ret = taskmonitor_start_unlocked(tmon);
	}

	mutex_unlock(&tmon->thread_lock);

	return ret;
}

// alias monitor_pid
static int taskmonitor_set_pid(struct taskmonitor *tmon, pid_t nr)
{
	struct pid *pid;

	pid = find_get_pid(nr);
	if (IS_ERR(pid))
		return PTR_ERR(pid);

	if (!pid)
		return -EINVAL;

	taskmonitor_unset_pid(tmon);

	tmon->pid = pid;

	taskmonitor_restart(tmon);

	return 0;
}

static unsigned long taskmonitor_samples_count_objects(struct shrinker *sh,
						       struct shrink_control *sc)
{
	unsigned long count;
	struct taskmonitor *tmon = container_of(sh, struct taskmonitor, samples_shrinker);

	taskmonitor_lock(tmon);

	count = tmon->samples_count ? tmon->samples_count : SHRINK_EMPTY;

	taskmonitor_unlock(tmon);

	return count;
}

static unsigned long taskmonitor_samples_scan_objects(struct shrinker *sh,
						       struct shrink_control *sc)
{
	struct taskmonitor *tmon = container_of(sh, struct taskmonitor, samples_shrinker);
	struct taskmonitor_sample *smp, *next;

	if (!taskmonitor_trylock(tmon))
		return SHRINK_STOP;

	sc->nr_scanned = 0;
	list_for_each_entry_safe(smp, next, &tmon->samples, list) {
		if (sc->nr_scanned >= sc->nr_to_scan)
			break;

		list_del(&smp->list);
		taskmonitor_sample_free(tmon, smp);

		tmon->samples_count--;
		sc->nr_scanned++;
	}

	taskmonitor_unlock(tmon);

	return sc->nr_scanned;
}

static struct taskmonitor *taskmonitor_new(void)
{
	int err;
	struct taskmonitor *tmon;

	tmon = kzalloc(sizeof(struct taskmonitor), GFP_KERNEL);
	if (IS_ERR(tmon))
		return tmon;

	mutex_init(&tmon->lock);
	mutex_init(&tmon->thread_lock);

	INIT_LIST_HEAD(&tmon->samples);

	tmon->samples_shrinker.count_objects = taskmonitor_samples_count_objects;
	tmon->samples_shrinker.scan_objects = taskmonitor_samples_scan_objects;
	tmon->samples_shrinker.batch = 0;
	tmon->samples_shrinker.seeks = DEFAULT_SEEKS;
	err = register_shrinker(&tmon->samples_shrinker, "taskmonitor");
	if (err)
		goto err_shrinker;

	tmon->samples_cache = kmem_cache_create("task_sample",
						sizeof(struct taskmonitor_sample),
						__alignof__(struct taskmonitor_sample),
						0, NULL);
	if (!tmon->samples_cache) {
		err = -ENOMEM;
		goto err_cache;
	}

	return tmon;

err_cache:
	unregister_shrinker(&tmon->samples_shrinker);
err_shrinker:
	mutex_destroy(&tmon->lock);
	mutex_destroy(&tmon->thread_lock);
	kfree(tmon);
	return ERR_PTR(err);
}

static void taskmonitor_free(struct taskmonitor *tmon)
{
	taskmonitor_stop_unlocked(tmon);
	taskmonitor_unset_pid(tmon);
	kmem_cache_destroy(tmon->samples_cache);
	unregister_shrinker(&tmon->samples_shrinker);
	mutex_destroy(&tmon->lock);
	mutex_destroy(&tmon->thread_lock);
	kfree(tmon);
}


static struct taskmonitor *taskmonitor_private;

static long taskmonitor_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	int ret = 0;
	pid_t pid;
	void __user *ptr = (void __user *)arg;
	struct taskmonitor *tmon = taskmonitor_private;
	struct taskmonitor_sample *smp;

	taskmonitor_lock(tmon);

	switch (cmd) {
	case TM_GET:
		if (list_empty(&tmon->samples)) {
			ret = -ENODATA;
			break;
		}

		smp = list_first_entry(&tmon->samples, struct taskmonitor_sample, list);

		struct task_sample usmp = {
			.utime = smp->utime,
			.stime = smp->stime,
		};

		ret = copy_to_user(ptr, &usmp, sizeof(usmp));
		break;

	case TM_START:
		ret = taskmonitor_start(tmon);
		break;

	case TM_STOP:
		taskmonitor_stop(tmon);
		break;

	case TM_PID:
		ret = copy_from_user(&pid, ptr, sizeof(pid));
		if (ret)
			break;

		if (pid >= 0) {
			ret = taskmonitor_set_pid(tmon, pid);
			break;
		}

		if (!tmon->pid) {
			ret = -ENODATA;
			break;
		}

		pid = pid_nr(tmon->pid);
		ret = copy_to_user(ptr, &pid, sizeof(pid));
		break;

	default:
		ret = -EINVAL;
		break;
	}

	taskmonitor_unlock(tmon);

	return ret;
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
	int ret, size, count = 0;
	struct taskmonitor *tmon = taskmonitor_private;
	struct taskmonitor_sample *smp;

	taskmonitor_lock(tmon);

	list_for_each_entry_reverse(smp, &tmon->samples, list) {
		size = PAGE_SIZE - count;
		ret = snprintf(buf, size,
			       "pid %d usr %llu sys %llu vm_total %lu vm_stack %lu vm_data %lu\n",
			       smp->pid, smp->utime, smp->stime, smp->vm_total, smp->vm_stack,
			       smp->vm_data);
		if (ret >= size)
			break;

		memmove(buf + size - ret, buf, ret);

		count += ret;
	}

	taskmonitor_unlock(tmon);

	memmove(buf, buf + PAGE_SIZE - count, count);
	buf[count] = '\0';

	return count;
}

static const struct kobj_attribute taskmonitor_attr = __ATTR_RW(taskmonitor);

static pid_t default_target;
module_param_named(target, default_target, int, 0644);

static int __init taskmonitor_init(void)
{
	int err;
	struct taskmonitor *tmon;

	tmon = taskmonitor_new();
	if (IS_ERR(tmon))
		return PTR_ERR(tmon);

	taskmonitor_private = tmon;

	if (default_target) {
		err = taskmonitor_set_pid(tmon, default_target);
		if (err)
			goto err_monitor;

		err = taskmonitor_start_unlocked(tmon);
		if (err)
			goto err_monitor;
	}

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
	taskmonitor_free(tmon);
	return err;
}
module_init(taskmonitor_init)

static void __exit taskmonitor_exit(void)
{
	struct taskmonitor *tmon = taskmonitor_private;

	unregister_chrdev(taskmonitor_major, "taskmonitor");
	sysfs_remove_file(kernel_kobj, &taskmonitor_attr.attr);
	taskmonitor_free(tmon);
}
module_exit(taskmonitor_exit)

MODULE_AUTHOR("Philipp Jungkamp <philipp.jungkamp@rwth-aachen.de>");
MODULE_DESCRIPTION("Monitor a task by pid");
MODULE_LICENSE("GPL");
