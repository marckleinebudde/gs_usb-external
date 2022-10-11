/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (c) 2022 Pengutronix,
 *               Marc Kleine-Budde <kernel@pengutronix.de>
 */

#include <linux/version.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 0, 0)

#include "../dev/dev.c"

#endif
