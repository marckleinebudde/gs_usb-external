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

/* generic implementation of netdev_ops::ndo_eth_ioctl for CAN devices
 * supporting hardware timestamps
 */
int can_eth_ioctl_hwts(struct net_device *netdev, struct ifreq *ifr, int cmd)
{
	struct hwtstamp_config hwts_cfg = { 0 };

	switch (cmd) {
	case SIOCSHWTSTAMP: /* set */
		if (copy_from_user(&hwts_cfg, ifr->ifr_data, sizeof(hwts_cfg)))
			return -EFAULT;
		if (hwts_cfg.tx_type == HWTSTAMP_TX_ON &&
		    hwts_cfg.rx_filter == HWTSTAMP_FILTER_ALL)
			return 0;
		return -ERANGE;

	case SIOCGHWTSTAMP: /* get */
		hwts_cfg.tx_type = HWTSTAMP_TX_ON;
		hwts_cfg.rx_filter = HWTSTAMP_FILTER_ALL;
		if (copy_to_user(ifr->ifr_data, &hwts_cfg, sizeof(hwts_cfg)))
			return -EFAULT;
		return 0;

	default:
		return -EOPNOTSUPP;
	}
}
EXPORT_SYMBOL(can_eth_ioctl_hwts);

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
