# SPDX-License-Identifier: GPL-2.0-only

ifneq ($(KERNELRELEASE),)

export CONFIG_CAN_GS_USB = m

obj-m += drivers/net/can/usb/

else

KDIR ?= /lib/modules/$(shell uname -r)/build

modules:

modules modules_install clean:
	$(MAKE) -C $(KDIR) M=$(PWD) $(@)

endif
