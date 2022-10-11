/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (c) 2022 Pengutronix,
 *               Marc Kleine-Budde <kernel@pengutronix.de>
 */
#ifndef _COMPAT_CAN_DEV_H
#define _COMPAT_CAN_DEV_H

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 0, 0)
int can_eth_ioctl_hwts(struct net_device *netdev, struct ifreq *ifr, int cmd);
int can_ethtool_op_get_ts_info_hwts(struct net_device *dev, struct ethtool_ts_info *info);
#endif

#endif
