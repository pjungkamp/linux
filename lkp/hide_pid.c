// SPDX-License-Identifier: GPL-2.0

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/slab.h>

struct hide_pid_dir_context {
	struct dir_context *real_ctx;
	struct dir_context ctx;
};

static pid_t target;
module_param(target, int, 0600);

static bool hide_pid_dir_context_actor(struct dir_context *ctx,
				       const char *name, int name_len,
				       loff_t pos, u64 ino, unsigned type)
{
	pid_t pid;
	struct hide_pid_dir_context *priv =
		container_of(ctx, struct hide_pid_dir_context, ctx);
	priv->real_ctx->pos = priv->ctx.pos;

	if (!kstrtoint(name, 10, &pid) && pid == target)
		return true;

	return priv->real_ctx->actor(priv->real_ctx, name, name_len, pos, ino,
				     type);
}

static const struct file_operations *hide_pid_real_fops;

static int hide_pid_iterate_shared(struct file *file,
				   struct dir_context *real_ctx)
{
	int ret;

	struct hide_pid_dir_context ctx = {
		.real_ctx = real_ctx,
		.ctx =
			(struct dir_context){
				.actor = hide_pid_dir_context_actor,
				.pos = real_ctx->pos,
			}
	};

	ret = hide_pid_real_fops->iterate_shared(file, &ctx.ctx);
	real_ctx->pos = ctx.ctx.pos;

	return ret;
}

static int __init hide_pid_init(void)
{
	int err;
	struct file *proc;
	struct file_operations *fops;

	proc = filp_open("/proc", O_RDONLY, 0);
	if (IS_ERR(proc)) {
		err = PTR_ERR(proc);
		goto err_proc;
	}

	fops = kzalloc(sizeof(struct file_operations), GFP_KERNEL);
	if (!fops) {
		err = -ENOMEM;
		goto err_fops;
	}

	hide_pid_real_fops = proc->f_op;
	*fops = *proc->f_op;

	fops->iterate_shared = hide_pid_iterate_shared;
	proc->f_op = fops;
	proc->f_inode->i_fop = fops;

	filp_close(proc, NULL);

	return 0;

err_fops:
	filp_close(proc, NULL);
err_proc:
	return err;
}
module_init(hide_pid_init);

static void __exit hide_pid_exit(void)
{
	struct file *proc;
	const struct file_operations *fops;

	proc = filp_open("/proc", O_RDONLY, 0);
	if (IS_ERR(proc))
		return;

	fops = proc->f_op;
	proc->f_op = hide_pid_real_fops;
	proc->f_inode->i_fop = hide_pid_real_fops;
	kfree(fops);

	filp_close(proc, NULL);
}
module_exit(hide_pid_exit);

MODULE_AUTHOR("Philipp Jungkamp <philipp.jungkamp@rwth-aachen.de>");
MODULE_DESCRIPTION("Hide a pid from procfs");
MODULE_LICENSE("GPL");

