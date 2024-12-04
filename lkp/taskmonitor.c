// SPDX-License-Identifier: GPL-2.0

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/debugfs.h>
#include <linux/err.h>
#include <linux/fs.h>
#include <linux/gfp_types.h>
#include <linux/kernel.h>
#include <linux/kobject.h>
#include <linux/kref.h>
#include <linux/kthread.h>
#include <linux/list.h>
#include <linux/mempool.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/pid.h>
#include <linux/sched.h>
#include <linux/seq_file.h>
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
	mempool_t samples_pool;
	struct task_struct *thread;
};

struct taskmonitor_sample {
	pid_t pid;
	u64 utime;
	u64 stime;
	unsigned long vm_total;
	unsigned long vm_stack;
	unsigned long vm_data;

	struct taskmonitor *tmon;
	struct kref ref;
	struct list_head list;
};

static struct taskmonitor_sample *
taskmonitor_sample_new(struct taskmonitor *tmon)
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

	ret = mempool_alloc(&tmon->samples_pool, GFP_KERNEL);
	if (!ret) {
		ret = ERR_PTR(-ENOMEM);
		goto err_pid_alive;
	}

	ret->pid = pid_nr(tmon->pid);
	ret->utime = task->utime;
	ret->stime = task->stime;
	ret->vm_total = task->mm->total_vm;
	ret->vm_stack = task->mm->stack_vm;
	ret->vm_data = task->mm->data_vm;

	ret->tmon = tmon;
	kref_init(&ret->ref);

err_pid_alive:
	put_task_struct(task);
err_pid_task:
	return ret;
}

static void taskmonitor_sample_free(struct taskmonitor_sample *smp)
{
	mempool_free(smp, &smp->tmon->samples_pool);
}

static void taskmonitor_sample_release(struct kref *ref)
{
	struct taskmonitor_sample *smp =
		container_of(ref, struct taskmonitor_sample, ref);

	taskmonitor_sample_free(smp);
}

static void taskmonitor_sample_get(struct taskmonitor_sample *smp)
{
	kref_get(&smp->ref);
}

static int taskmonitor_sample_put(struct taskmonitor_sample *smp)
{
	return kref_put(&smp->ref, taskmonitor_sample_release);
}

static void taskmonitor_samples_add(struct taskmonitor *tmon,
				    struct taskmonitor_sample *smp)
{
	taskmonitor_sample_get(smp);
	tmon->samples_count++;
	list_add_tail(&smp->list, &tmon->samples);
}

static void taskmonitor_samples_reset(struct taskmonitor *tmon)
{
	struct taskmonitor_sample *smp, *next;

	tmon->samples_count = 0;
	list_for_each_entry_safe(smp, next, &tmon->samples, list) {
		list_del(&smp->list);
		taskmonitor_sample_put(smp);
	}
}

static void taskmonitor_unset_pid(struct taskmonitor *tmon)
{
	if (!tmon->pid)
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

		taskmonitor_sample_put(smp);

		schedule_timeout_uninterruptible(HZ);
	}

	return 0;
}

static int taskmonitor_start(struct taskmonitor *tmon)
{
	struct task_struct *thread;

	if (tmon->thread)
		return 0;

	thread = kthread_create(taskmonitor_threadfn, tmon, "tmon/%d",
				pid_nr(tmon->pid));
	if (IS_ERR(thread))
		return PTR_ERR(thread);

	get_task_struct(thread);
	wake_up_process(thread);
	tmon->thread = thread;

	return 0;
}

static void taskmonitor_stop(struct taskmonitor *tmon)
{
	if (!tmon->thread)
		return;

	kthread_stop(tmon->thread);
	put_task_struct(tmon->thread);

	tmon->thread = NULL;
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

	return 0;
}

static unsigned long
taskmonitor_samples_count_objects(struct shrinker *sh,
				  struct shrink_control *sc)
{
	unsigned long count;
	struct taskmonitor *tmon =
		container_of(sh, struct taskmonitor, samples_shrinker);

	taskmonitor_lock(tmon);

	count = tmon->samples_count ? tmon->samples_count : SHRINK_EMPTY;

	taskmonitor_unlock(tmon);

	return count;
}

static unsigned long taskmonitor_samples_scan_objects(struct shrinker *sh,
						      struct shrink_control *sc)
{
	struct taskmonitor *tmon =
		container_of(sh, struct taskmonitor, samples_shrinker);
	struct taskmonitor_sample *smp, *next;
	unsigned long smp_freed = 0;

	if (!taskmonitor_trylock(tmon))
		return SHRINK_STOP;

	sc->nr_scanned = 0;
	list_for_each_entry_safe(smp, next, &tmon->samples, list) {
		if (sc->nr_scanned >= sc->nr_to_scan)
			break;

		list_del(&smp->list);
		smp_freed += taskmonitor_sample_put(smp);

		tmon->samples_count--;
		sc->nr_scanned++;
	}

	taskmonitor_unlock(tmon);

	return smp_freed;
}

static struct taskmonitor *taskmonitor_new(pid_t nr)
{
	int err;
	struct taskmonitor *tmon;

	tmon = kzalloc(sizeof(struct taskmonitor), GFP_KERNEL);
	if (!tmon)
		return ERR_PTR(-ENOMEM);

	mutex_init(&tmon->lock);

	INIT_LIST_HEAD(&tmon->samples);

	tmon->samples_shrinker.count_objects =
		taskmonitor_samples_count_objects;
	tmon->samples_shrinker.scan_objects = taskmonitor_samples_scan_objects;
	tmon->samples_shrinker.batch = 0;
	tmon->samples_shrinker.seeks = DEFAULT_SEEKS;
	err = register_shrinker(&tmon->samples_shrinker, "tmon/%d", nr);
	if (err)
		goto err_shrinker;

	tmon->samples_cache = KMEM_CACHE(taskmonitor_sample, 0);
	if (!tmon->samples_cache) {
		err = -ENOMEM;
		goto err_cache;
	}

	err = mempool_init_slab_pool(&tmon->samples_pool, 16,
				     tmon->samples_cache);
	if (err)
		goto err_pool;

	err = taskmonitor_set_pid(tmon, nr);
	if (err)
		goto err_init;

	err = taskmonitor_start(tmon);
	if (err)
		goto err_init;

	return tmon;

err_init:
	taskmonitor_stop(tmon);
	taskmonitor_unset_pid(tmon);
	mempool_exit(&tmon->samples_pool);
err_pool:
	kmem_cache_destroy(tmon->samples_cache);
err_cache:
	unregister_shrinker(&tmon->samples_shrinker);
err_shrinker:
	mutex_destroy(&tmon->lock);
	kfree(tmon);
	return ERR_PTR(err);
}

static void taskmonitor_free(struct taskmonitor *tmon)
{
	taskmonitor_stop(tmon);
	taskmonitor_unset_pid(tmon);
	mempool_exit(&tmon->samples_pool);
	kmem_cache_destroy(tmon->samples_cache);
	unregister_shrinker(&tmon->samples_shrinker);
	mutex_destroy(&tmon->lock);
	kfree(tmon);
}

static void *taskmonitor_seq_start(struct seq_file *s, loff_t *pos)
{
	struct taskmonitor *tmon = s->private;
	struct taskmonitor_sample *smp;
	unsigned long off = *pos;

	taskmonitor_lock(tmon);

	list_for_each_entry(smp, &tmon->samples, list) {
		if (!off--)
			return smp;
	}

	return NULL;
}

static void *taskmonitor_seq_next(struct seq_file *s, void *v, loff_t *pos)
{
	struct taskmonitor *tmon = s->private;
	struct taskmonitor_sample *smp = v;

	*pos += 1;

	if (list_is_last(&smp->list, &tmon->samples))
		return NULL;

	return list_next_entry(smp, list);
}

static void taskmonitor_seq_stop(struct seq_file *s, void *v)
{
	struct taskmonitor *tmon = s->private;

	taskmonitor_unlock(tmon);
}

static int taskmonitor_seq_show(struct seq_file *s, void *v)
{
	struct taskmonitor_sample *smp = v;

	seq_printf(
		s,
		"pid %d usr %llu sys %llu vm_total %lu vm_stack %lu vm_data %lu\n",
		smp->pid, smp->utime, smp->stime, smp->vm_total, smp->vm_stack,
		smp->vm_data);

	return 0;
}

static const struct seq_operations taskmonitor_sops = {
	.start = taskmonitor_seq_start,
	.next = taskmonitor_seq_next,
	.stop = taskmonitor_seq_stop,
	.show = taskmonitor_seq_show,
};

static int taskmonitor_open(struct inode *inode, struct file *file)
{
	int ret;
	struct seq_file *s;

	ret = seq_open(file, &taskmonitor_sops);
	if (ret)
		return ret;

	s = file->private_data;
	s->private = inode->i_private;

	return 0;
}

static const struct file_operations taskmonitor_fops = {
	.owner = THIS_MODULE,
	.open = taskmonitor_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = seq_release,
};

static struct taskmonitor *taskmonitor_private;
static struct dentry *taskmonitor_debugfs;
static pid_t target;
module_param(target, int, 0644);

static int __init taskmonitor_init(void)
{
	int err;
	struct taskmonitor *tmon;

	tmon = taskmonitor_new(target);
	if (IS_ERR(tmon)) {
		err = PTR_ERR(tmon);
		goto err_tmon;
	}

	taskmonitor_debugfs = debugfs_create_file("taskmonitor", 0444, NULL,
						  tmon, &taskmonitor_fops);
	if (IS_ERR(taskmonitor_debugfs)) {
		err = PTR_ERR(taskmonitor_debugfs);
		goto err_debugfs;
	}

	taskmonitor_private = tmon;

	return 0;

err_debugfs:
	taskmonitor_free(tmon);
err_tmon:
	return err;
}
module_init(taskmonitor_init)

static void __exit taskmonitor_exit(void)
{
	struct taskmonitor *tmon = taskmonitor_private;

	debugfs_remove(taskmonitor_debugfs);
	taskmonitor_free(tmon);
}
module_exit(taskmonitor_exit)

MODULE_AUTHOR("Philipp Jungkamp <philipp.jungkamp@rwth-aachen.de>");
MODULE_DESCRIPTION("Monitor a task by pid");
MODULE_LICENSE("GPL");
