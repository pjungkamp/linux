// SPDX-License-Identifier: GPL-2.0

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/dcache.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/string.h>

static int weasel_proc_whoami_show(struct seq_file *seq, void *data)
{
	seq_printf(seq, "I'm a weasel!\n");

	return 0;
}

static int weasel_proc_info_show(struct seq_file *seq, void *data)
{
	unsigned int n_buckets = 1 << (32 - d_hash_shift);
	unsigned int n_entries, n_entries_max, n_entries_total;
	struct dentry *dentry;
	struct hlist_bl_node *pos;

	rcu_read_lock();

	n_entries_max = 0;
	n_entries_total = 0;
	for (unsigned int bucket = 0; bucket < n_buckets; bucket++) {
		n_entries = 0;
		hlist_bl_for_each_entry_rcu(dentry, pos,
					    &dentry_hashtable[bucket], d_hash)
			n_entries++;

		n_entries_total += n_entries;

		if (n_entries > n_entries_max)
			n_entries_max = n_entries;
	}

	rcu_read_unlock();

	seq_printf(
		seq,
		"address: 0x%px\nsize: %d\nentries: %d\nlongest: %d entries\n",
		dentry_hashtable, n_buckets, n_entries_total, n_entries_max);

	return 0;
}

static int weasel_proc_dcache_show(struct seq_file *seq, void *data)
{
	int ret = 0;
	unsigned int n_buckets = 1 << (32 - d_hash_shift);
	struct dentry *dentry;
	struct hlist_bl_node *pos;
	char *path_buf, *dentry_path;

	path_buf = kmalloc(PATH_MAX, GFP_KERNEL);
	if (!path_buf) {
		ret = -ENOMEM;
		goto out_path_buf;
	}

	rcu_read_lock();

	for (unsigned int bucket = 0; bucket < n_buckets; bucket++) {
		hlist_bl_for_each_entry_rcu(dentry, pos,
					    &dentry_hashtable[bucket], d_hash) {
			dentry_path =
				dentry_path_raw(dentry, path_buf, PATH_MAX);
			if (IS_ERR(dentry_path))
				continue;

			seq_printf(seq, "%s\n", dentry_path);
		}
	}

	rcu_read_unlock();

	kfree(path_buf);

out_path_buf:
	return ret;
}

static int weasel_proc_pwd_show(struct seq_file *seq, void *data)
{
	int ret = 0;
	unsigned int n_buckets = 1 << (32 - d_hash_shift);
	struct dentry *dentry;
	struct hlist_bl_node *pos;

	rcu_read_lock();

	for (unsigned int bucket = 0; bucket < n_buckets; bucket++) {
		hlist_bl_for_each_entry_rcu(dentry, pos,
					    &dentry_hashtable[bucket], d_hash) {
			if (dentry->d_inode)
				continue;

			seq_printf(seq, "%pd\n", dentry);
		}
	}

	rcu_read_unlock();

	return ret;
}

static struct proc_dir_entry *weasel_proc_dir;
static struct proc_dir_entry *weasel_proc_whoami;
static struct proc_dir_entry *weasel_proc_info;
static struct proc_dir_entry *weasel_proc_dcache;
static struct proc_dir_entry *weasel_proc_pwd;

static int __init weasel_init(void)
{
	int ret = 0;

	weasel_proc_dir = proc_mkdir("weasel", NULL);
	if (!weasel_proc_dir) {
		ret = -ENOMEM;
		goto err_proc_dir;
	}

	weasel_proc_whoami = proc_create_single("whoami", 0400, weasel_proc_dir,
						weasel_proc_whoami_show);
	if (!weasel_proc_whoami) {
		ret = -ENOMEM;
		goto err_proc_whoami;
	}

	weasel_proc_info = proc_create_single("info", 0400, weasel_proc_dir,
					      weasel_proc_info_show);
	if (!weasel_proc_whoami) {
		ret = -ENOMEM;
		goto err_proc_info;
	}

	weasel_proc_dcache = proc_create_single("dcache", 0400, weasel_proc_dir,
						weasel_proc_dcache_show);
	if (!weasel_proc_dcache) {
		ret = -ENOMEM;
		goto err_proc_dcache;
	}

	weasel_proc_pwd = proc_create_single("pwd", 0400, weasel_proc_dir,
					     weasel_proc_pwd_show);
	if (!weasel_proc_pwd) {
		ret = -ENOMEM;
		goto err_proc_pwd;
	}

	return 0;

err_proc_pwd:
	proc_remove(weasel_proc_dcache);
err_proc_dcache:
	proc_remove(weasel_proc_info);
err_proc_info:
	proc_remove(weasel_proc_whoami);
err_proc_whoami:
	proc_remove(weasel_proc_dir);
err_proc_dir:
	return ret;
}
module_init(weasel_init);

static void __exit weasel_exit(void)
{
	proc_remove(weasel_proc_pwd);
	proc_remove(weasel_proc_dcache);
	proc_remove(weasel_proc_info);
	proc_remove(weasel_proc_whoami);
	proc_remove(weasel_proc_dir);
}
module_exit(weasel_exit);

MODULE_AUTHOR(
	"Definitely not Philipp Jungkamp <philipp.jungkamp@rwth-aachen.de>");
MODULE_DESCRIPTION("I'm nOT a RoOTkit! PrOmiSE!");
MODULE_LICENSE("GPL");
