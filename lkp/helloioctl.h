// SPDX-License-Identifier: GPL-2.0

#include <asm/ioctl.h>

#define HELLO_LEN 4096
#define HELLO _IOC(_IOC_READ, 'N', 1, HELLO_LEN)
