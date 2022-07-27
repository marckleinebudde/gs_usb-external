// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (C) 2005 Marc Kleine-Budde, Pengutronix
 * Copyright (C) 2006 Andrey Volkov, Varma Electronics
 * Copyright (C) 2008-2009 Wolfgang Grandegger <wg@grandegger.com>
 */

#include <linux/can.h>
#include <linux/can/dev.h>
#include <linux/can/skb.h>
#include <linux/ethtool.h>
#include <linux/kernel.h>
#include <linux/netdevice.h>

/* generic implementation of ethtool_ops::get_ts_info for CAN devices
 * supporting hardware timestamps
 */
int can_ethtool_op_get_ts_info_hwts(struct net_device *dev,
				    struct ethtool_ts_info *info)
{
	info->so_timestamping =
		SOF_TIMESTAMPING_TX_SOFTWARE |
		SOF_TIMESTAMPING_RX_SOFTWARE |
		SOF_TIMESTAMPING_SOFTWARE |
		SOF_TIMESTAMPING_TX_HARDWARE |
		SOF_TIMESTAMPING_RX_HARDWARE |
		SOF_TIMESTAMPING_RAW_HARDWARE;
	info->phc_index = -1;
	info->tx_types = BIT(HWTSTAMP_TX_ON);
	info->rx_filters = BIT(HWTSTAMP_FILTER_ALL);

	return 0;
}
EXPORT_SYMBOL(can_ethtool_op_get_ts_info_hwts);
