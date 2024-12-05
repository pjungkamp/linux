// SPDX-License-Identifier: GPL-2.0

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/debugfs.h>
#include <linux/err.h>
#include <linux/fs.h>
#include <linux/gfp_types.h>
#include <linux/kernel.h>
#include <linux/kobject.h>
#include <linux/kref.h>
#include <linux/kstrtox.h>
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
	struct dentry *file;
	struct kref ref;

	struct list_head list;
};

struct taskmonitor_shared {
	struct mutex lock;
	struct list_head list;
	struct dentry *dir;
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

static void taskmonitor_free(struct taskmonitor *tmon);

static struct taskmonitor_sample *
taskmonitor_sample_new(struct taskmonitor *tmon)
{
	struct taskmonitor_sample *ret;
	struct task_struct *task;

	task = get_pid_task(tmon->pid, PIDTYPE_PID);
	if (IS_ERR_OR_NULL(task)) {
		ret = ERR_CAST(task);
		goto err_pid_task;
	}

	if (!pid_alive(task)) {
		ret = NULL;
		goto err_pid_alive;
	}

	ret = mempool_alloc(&tmon->samples_pool, GFP_KERNEL);
	if (!ret) {
		ret = ERR_PTR(-ENOMEM);
		goto err_pid_alive;
	}

	memset(ret, 0, sizeof(*ret));

	ret->pid = pid_nr(tmon->pid);
	ret->utime = task->utime;
	ret->stime = task->stime;

	if (task->mm) {
		ret->vm_total = task->mm->total_vm;
		ret->vm_stack = task->mm->stack_vm;
		ret->vm_data = task->mm->data_vm;
	}

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

static int taskmonitor_get_unless_zero(struct taskmonitor *tmon)
{
	return kref_get_unless_zero(&tmon->ref);
}

static void taskmonitor_release(struct kref *ref)
{
	struct taskmonitor *tmon = container_of(ref, struct taskmonitor, ref);

	taskmonitor_free(tmon);
}

static int taskmonitor_put(struct taskmonitor *tmon)
{
	return kref_put(&tmon->ref, taskmonitor_release);
}

static unsigned long
taskmonitor_samples_count_objects(struct shrinker *sh,
				  struct shrink_control *sc)
{
	unsigned long count;
	struct taskmonitor *tmon =
		container_of(sh, struct taskmonitor, samples_shrinker);

	mutex_lock(&tmon->lock);

	count = tmon->samples_count ? tmon->samples_count : SHRINK_EMPTY;

	mutex_unlock(&tmon->lock);

	return count;
}

static unsigned long taskmonitor_samples_scan_objects(struct shrinker *sh,
						      struct shrink_control *sc)
{
	struct taskmonitor *tmon =
		container_of(sh, struct taskmonitor, samples_shrinker);
	struct taskmonitor_sample *smp, *next;
	unsigned long smp_freed = SHRINK_STOP;

	if (!taskmonitor_get_unless_zero(tmon))
		goto err_get;

	if (!mutex_trylock(&tmon->lock))
		goto err_trylock;

	smp_freed = 0;
	sc->nr_scanned = 0;
	list_for_each_entry_safe(smp, next, &tmon->samples, list) {
		if (sc->nr_scanned >= sc->nr_to_scan)
			break;

		list_del(&smp->list);
		smp_freed += taskmonitor_sample_put(smp);

		tmon->samples_count--;
		sc->nr_scanned++;
	}

	mutex_unlock(&tmon->lock);
err_trylock:
	taskmonitor_put(tmon);
err_get:
	return smp_freed;
}

static void *taskmonitor_seq_start(struct seq_file *s, loff_t *pos)
{
	struct taskmonitor *tmon = s->private;
	struct taskmonitor_sample *smp;
	unsigned long off = *pos;

	if (!taskmonitor_get_unless_zero(tmon))
		return NULL;

	mutex_lock(&tmon->lock);

	list_for_each_entry(smp, &tmon->samples, list) {
		if (!off--)
			return smp; // keep the mutex locked until seq_stop
	}

	mutex_unlock(&tmon->lock);

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

	mutex_unlock(&tmon->lock);
	taskmonitor_put(tmon);
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

static struct taskmonitor *taskmonitor_new(const char *pid, struct dentry *dir)
{
	int err;
	pid_t pid_nr;
	struct taskmonitor *tmon;

	err = kstrtoint(pid, 0, &pid_nr);
	if (err)
		goto err_alloc;

	tmon = kzalloc(sizeof(struct taskmonitor), GFP_KERNEL);
	if (!tmon) {
		err = -ENOMEM;
		goto err_alloc;
	}

	kref_init(&tmon->ref);
	mutex_init(&tmon->lock);
	INIT_LIST_HEAD(&tmon->samples);

	tmon->samples_shrinker.count_objects =
		taskmonitor_samples_count_objects;
	tmon->samples_shrinker.scan_objects = taskmonitor_samples_scan_objects;
	tmon->samples_shrinker.batch = 0;
	tmon->samples_shrinker.seeks = DEFAULT_SEEKS;
	err = register_shrinker(&tmon->samples_shrinker, "tmon-%d", pid_nr);
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

	err = taskmonitor_set_pid(tmon, pid_nr);
	if (err)
		goto err_init;

	tmon->file = debugfs_create_file(pid, 0444, dir, tmon, &taskmonitor_fops);
	if (IS_ERR(tmon->file)) {
		err = PTR_ERR(tmon->file);
		goto err_init;
	}

	return tmon;

err_init:
	taskmonitor_unset_pid(tmon);
	mempool_exit(&tmon->samples_pool);
err_pool:
	kmem_cache_destroy(tmon->samples_cache);
err_cache:
	unregister_shrinker(&tmon->samples_shrinker);
err_shrinker:
	mutex_destroy(&tmon->lock);
	kfree(tmon);
err_alloc:
	return ERR_PTR(err);
}

static void taskmonitor_free(struct taskmonitor *tmon)
{
	debugfs_remove(tmon->file);
	taskmonitor_unset_pid(tmon);
	mempool_exit(&tmon->samples_pool);
	kmem_cache_destroy(tmon->samples_cache);
	unregister_shrinker(&tmon->samples_shrinker);
	mutex_destroy(&tmon->lock);
	kfree(tmon);
}

// alias monitor_fn
static int taskmonitor_threadfn(void *arg)
{
	struct taskmonitor_shared *shared = arg;
	struct taskmonitor *tmon, *next;
	struct taskmonitor_sample *smp;

	while (!kthread_should_stop()) {
		mutex_lock(&shared->lock);

		list_for_each_entry_safe(tmon, next, &shared->list, list) {
			smp = taskmonitor_sample_new(tmon);
			if (IS_ERR_OR_NULL(smp)) {
				list_del(&tmon->list);
				taskmonitor_put(tmon);
				continue;
			}

			mutex_lock(&tmon->lock);
			taskmonitor_samples_add(tmon, smp);
			mutex_unlock(&tmon->lock);

			taskmonitor_sample_put(smp);
		}

		mutex_unlock(&shared->lock);

		schedule_timeout_uninterruptible(HZ);
	}

	list_for_each_entry_safe(tmon, next, &shared->list, list) {
		mutex_lock(&tmon->lock);
		list_del(&tmon->list);
		mutex_unlock(&tmon->lock);
		taskmonitor_put(tmon);
	}

	return 0;
}

static ssize_t taskmonitor_control_write(struct file *file, const char *buf, size_t len, loff_t *off)
{
	ssize_t ret;
	struct taskmonitor_shared *shared = file->private_data;
	struct taskmonitor *tmon, *next;
	char *pid_str;
	pid_t pid;

	pid_str = memdup_user_nul(buf, len);
	if (IS_ERR(pid_str)) {
		ret = PTR_ERR(pid_str);
		goto err_pid_str;
	}

	ret = kstrtoint(pid_str, 0, &pid);
	if (ret)
		goto err_kstrtoint;

	mutex_lock(&shared->lock);

	if (pid >= 0) {
		tmon = taskmonitor_new(strim(pid_str), shared->dir);
		if (IS_ERR(tmon)) {
			ret = PTR_ERR(tmon);
			goto err_new;
		}

		list_add(&tmon->list, &shared->list);

		ret = len;
	} else {
		ret = -EINVAL;

		list_for_each_entry_safe(tmon, next, &shared->list, list) {
			if (pid_nr(tmon->pid) == -pid) {
				list_del(&tmon->list);
				taskmonitor_put(tmon);
				ret = len;
				break;
			}
		}
	}

err_new:
	mutex_unlock(&shared->lock);
err_kstrtoint:
	kfree(pid_str);
err_pid_str:
	return ret;
}

static const struct file_operations taskmonitor_control_fops = {
	.owner = THIS_MODULE,
	.open = simple_open,
	.write = taskmonitor_control_write,
	.llseek = no_llseek,
};

static struct taskmonitor_shared taskmonitor_shared;
static struct dentry *taskmonitor_debugfs_control;
static struct task_struct *taskmonitor_thread;

static int __init taskmonitor_init(void)
{
	int err;

	mutex_init(&taskmonitor_shared.lock);
	INIT_LIST_HEAD(&taskmonitor_shared.list);

	taskmonitor_shared.dir = debugfs_create_dir("taskmonitor", NULL);
	if (IS_ERR(taskmonitor_shared.dir)) {
		err = PTR_ERR(taskmonitor_shared.dir);
		goto err_debugfs;
	}

	taskmonitor_thread = kthread_run(taskmonitor_threadfn, &taskmonitor_shared, "taskmonitor");
	if (IS_ERR(taskmonitor_thread)) {
		err = PTR_ERR(taskmonitor_thread);
		goto err_kthread;
	}

	taskmonitor_debugfs_control = debugfs_create_file("control", 0200, taskmonitor_shared.dir, &taskmonitor_shared, &taskmonitor_control_fops);
	if (IS_ERR(taskmonitor_debugfs_control)) {
		err = PTR_ERR(taskmonitor_debugfs_control);
		goto err_debugfs_file;
	}

	return 0;

err_debugfs_file:
	kthread_stop(taskmonitor_thread);
err_kthread:
	debugfs_remove(taskmonitor_shared.dir);
err_debugfs:
	return err;
}
module_init(taskmonitor_init)

static void __exit taskmonitor_exit(void)
{
	debugfs_remove(taskmonitor_debugfs_control);
	kthread_stop(taskmonitor_thread);
	debugfs_remove(taskmonitor_shared.dir);
	mutex_destroy(&taskmonitor_shared.lock);
}
module_exit(taskmonitor_exit)

MODULE_AUTHOR("Philipp Jungkamp <philipp.jungkamp@rwth-aachen.de>");
MODULE_DESCRIPTION("Monitor a task by pid");
MODULE_LICENSE("GPL");
