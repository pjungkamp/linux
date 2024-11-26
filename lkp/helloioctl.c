// SPDX-License-Identifier: GPL-2.0

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/kernel.h>
#include <linux/module.h>

#include "helloioctl.h"

static const char helloioctl_string[] = "Hello ioctl!";

static long helloioctl_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	int err;

	switch (cmd) {
	case HELLO:
		err = copy_to_user((void *) arg, helloioctl_string, sizeof(helloioctl_string));
		if (err)
			return err;

		break;
	default:
		return -ENOTTY;
	}

	return 0;
}

static const struct file_operations helloioctl_fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = helloioctl_ioctl,
};

static int helloioctl_major;

static int __init helloioctl_init(void)
{
	helloioctl_major = register_chrdev(0, "hello", &helloioctl_fops);
	if (helloioctl_major < 0)
		return helloioctl_major;

	return 0;
}
module_init(helloioctl_init)

static void __exit helloioctl_exit(void)
{
	unregister_chrdev(helloioctl_major, "hello");
}
module_exit(helloioctl_exit)

MODULE_AUTHOR("Philipp Jungkamp <philipp.jungkamp@rwth-aachen.de>");
MODULE_DESCRIPTION("Return \"Hello ioctl\" from an ioctl");
MODULE_LICENSE("GPL");
