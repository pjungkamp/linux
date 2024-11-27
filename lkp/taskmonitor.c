// SPDX-License-Identifier: GPL-2.0

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/err.h>
#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/module.h>
#include <linux/pid.h>
#include <linux/sched.h>
#include <linux/slab.h>

struct taskmonitor {
	struct pid *pid;
	struct task_struct *thread;
};

static void taskmonitor_unset_pid(struct taskmonitor *tmon)
{
	if (!tmon->pid)
		return;

	put_pid(tmon->pid);
	tmon->pid = NULL;
}

// alias monitor_fn
static int taskmonitor_threadfn(void *arg)
{
	struct taskmonitor *tmon = arg;
	struct task_struct *task;

	while (!kthread_should_stop()) {
		task = get_pid_task(tmon->pid, PIDTYPE_PID);

		if (IS_ERR_OR_NULL(task) || !pid_alive(task)) {
			taskmonitor_unset_pid(tmon);
			return PTR_ERR_OR_ZERO(task);
		}

		printk(KERN_INFO "pid %d usr %llu sys %llu", task->pid, task->utime, task->stime);

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

static pid_t default_target;
module_param_named(target, default_target, int, 0644);

static struct taskmonitor *taskmonitor_private;

static int __init taskmonitor_init(void)
{
	int err;

	taskmonitor_private = kzalloc(sizeof(struct taskmonitor), GFP_KERNEL);
	if (IS_ERR(taskmonitor_private)) {
		err = PTR_ERR(taskmonitor_private);
		goto err_kzalloc;
	}


	if (default_target != 0) {
		err = taskmonitor_set_pid(taskmonitor_private, default_target);
		if (err)
			goto err_monitor;

		err = taskmonitor_start(taskmonitor_private);
		if (err)
			goto err_monitor;
	}

	return 0;

err_monitor:
	taskmonitor_stop(taskmonitor_private);
	taskmonitor_unset_pid(taskmonitor_private);
	kfree(taskmonitor_private);
err_kzalloc:
	return err;
}
module_init(taskmonitor_init)

static void __exit taskmonitor_exit(void)
{
	taskmonitor_stop(taskmonitor_private);
	taskmonitor_unset_pid(taskmonitor_private);
	kfree(taskmonitor_private);
}
module_exit(taskmonitor_exit)

MODULE_AUTHOR("Philipp Jungkamp <philipp.jungkamp@rwth-aachen.de>");
MODULE_DESCRIPTION("Monitor a task by pid");
MODULE_LICENSE("GPL");
