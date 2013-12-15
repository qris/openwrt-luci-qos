include $(TOPDIR)/rules.mk

# Find and include settings from iproute2 to get its build directory
IPROUTE2_SRC_DIR = $(TOPDIR)/package/network/utils/iproute2
IPROUTE2_BUILD_DIR := $(BUILD_DIR)/iproute2-$(shell \
	grep "^PKG_VERSION" $(IPROUTE2_SRC_DIR)/Makefile | sed -e 's/.*:=//')
export IPROUTE2_BUILD_DIR

LUCI_TOPDIR=../../..

PKG_NAME := luci-app-qwirx-qos
PKG_VERSION := $(shell git rev-parse --verify HEAD || echo unknown)
PKG_RELEASE := 1

PKG_BUILD_PARALLEL := 0

PKG_BUILD_DIR := $(BUILD_DIR)/$(PKG_NAME)
# PKG_BUILD_DEPENDS:=$(if $(STAGING_DIR_ROOT),luci/luci,iproute2)
# PKG_INSTALL_DIR:=$(PKG_BUILD_DIR)/ipkg-install

LUA_TARGET := source
LUCI_CFLAGS :=
LUCI_BUILD_PACKAGES :=
LUCI_SELECTED_MODULES :=

include $(INCLUDE_DIR)/package.mk

define application
  define Package/$(1)
    SECTION:=luci
    CATEGORY:=LuCI
    URL:=http://github.com/qwirx/$(PKG_NAME)
    MAINTAINER:=Qwirx <chris+$(PKG_NAME)@qwirx.com>
    SUBMENU:=3. Applications
    TITLE:=$(if $(2),$(2),LuCI $(1) application)
    DEPENDS:=$(3)
  endef

  define Package/$(1)/install
	$(call Package/luci/install/template,$$(1),applications/$(1))
  endef

  ifneq ($(CONFIG_PACKAGE_$(1)),)
    LUCI_SELECTED_MODULES+=applications/$(1)
  endif

  LUCI_BUILD_PACKAGES += $(1)
endef

define Package/$(PKG_NAME)/conffiles
/etc/config/$(PKG_NAME)
endef

define Package/$(PKG_NAME)/description
LuCI module for measuring and tuning Quality of Service configuration.
endef

$(eval $(call application,$(PKG_NAME),Qwirx QoS Module,+tc luci))

# PKG_CONFIG_DEPENDS=$(patsubst %,CONFIG_PACKAGE_%,$(LUCI_BUILD_PACKAGES))

define Build/Prepare
	cp -au src/* $(PKG_BUILD_DIR)
endef

define Build/Configure
  $(call Build/Configure/Default,--with-linux-headers=$(LINUX_DIR))
endef

define Package/$(PKG_NAME)/install
  # $(INSTALL_DIR) $(1)/usr/sbin
  # $(INSTALL_BIN) $(PKG_BUILD_DIR)/brctl/brctl $(1)/usr/sbin/
endef

$(eval $(call BuildPackage,$(PKG_NAME)))

