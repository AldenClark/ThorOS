# SPDX-License-Identifier: GPL-2.0-only
define KernelPackage/tyfza1-usb-led
  SUBMENU:=LED modules
  TITLE:=TYFZA1 USB presence and activity LED
  DEPENDS:=@TARGET_rtl9617c +kmod-usb-core
  KCONFIG:=CONFIG_LEDS_TRIGGER_TYFZA1_USB
  FILES:=$(LINUX_DIR)/drivers/leds/ledtrig-tyfza1-usb.ko
  AUTOLOAD:=$(call AutoLoad,60,ledtrig-tyfza1-usb)
endef

$(eval $(call KernelPackage,tyfza1-usb-led))
