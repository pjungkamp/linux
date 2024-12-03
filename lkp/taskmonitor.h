// SPDX-License-Identifier: GPL-2.0

#include <asm/ioctl.h>

#define TM_IOCTL_MAGIC 'N'
#define TM_GET   (_IOR (TM_IOCTL_MAGIC, 1, struct task_sample))
#define TM_START (_IO  (TM_IOCTL_MAGIC, 2))
#define TM_STOP  (_IO  (TM_IOCTL_MAGIC, 3))
#define TM_PID   (_IOWR(TM_IOCTL_MAGIC, 4, pid_t))

struct task_sample {
	unsigned long long utime;
	unsigned long long stime;
};
