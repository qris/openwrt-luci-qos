# Compile the C portions of luci-app-qwirx-qos
# Based on feeds/luci/libs/web/Makefile, Apache License

LUCI = $(TOPDIR)/feeds/luci

ifneq (,$(wildcard $(LUCI)/build/config.mk))
include $(LUCI)/build/config.mk
include $(LUCI)/build/module.mk
include $(LUCI)/build/gccconfig.mk
else
include standalone.mk-foo
endif

QOS_LDFLAGS    =
QOS_CFLAGS     = -I$(IPROUTE2_BUILD_DIR)/include -I$(IPROUTE2_BUILD_DIR)/tc
QOS_SO         = qwirx_qos_c.so
QOS_PO2LMO     = po2lmo
QOS_PO2LMO_OBJ = src/po2lmo.o
QOS_OBJ        = tc_wrapper.o

%.o: %.c
	echo LUA_CFLAGS = $(LUA_CFLAGS)
	$(COMPILE) $(QOS_CFLAGS) $(LUA_CFLAGS) $(FPIC) -c -o $@ $<

compile: build-clean $(QOS_OBJ)
	$(LINK) $(SHLIB_FLAGS) $(QOS_LDFLAGS) -o $(QOS_SO) $(QOS_OBJ)
	cp $(QOS_SO) dist$(LUCI_LIBRARYDIR)

install: build
	cp -pR dist$(LUA_LIBRARYDIR)/* $(LUA_LIBRARYDIR)

clean: build-clean

build-clean:
	rm -f src/*.o src/$(QOS_SO)

host-compile: build-clean host-clean $(QOS_LMO_OBJ) $(QOS_PO2LMO_OBJ)
	$(LINK) -o src/$(QOS_PO2LMO) $(QOS_LMO_OBJ) $(QOS_PO2LMO_OBJ)

host-install: host-compile
	cp src/$(QOS_PO2LMO) ../../build/$(QOS_PO2LMO)

host-clean:
	rm -f ../../build/$(QOS_PO2LMO)
