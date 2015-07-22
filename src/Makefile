BLUEZ_PATH=../bluez-lib
GLIB_PATH= ../glib-2.0.0

PKG_CONFIG_PATH=/usr/arm-linux-gnueabi/lib

BLUEZ_SRCS  = lib/bluetooth.c lib/hci.c lib/sdp.c lib/uuid.c
BLUEZ_SRCS += attrib/att.c attrib/gatt.c attrib/gattrib.c attrib/utils.c
BLUEZ_SRCS += btio/btio.c src/log.c

LIBC=-L/usr/arm-linux-gnueabi/lib/libc-2.19.so

GLIB_SHARE=/usr/arm-linux-gnueabi/lib/libglib-2.0.so.0.4000.0
THREAD_LDADD=/usr/arm-linux-gnueabi/lib/libpthread.so.0

IMPORT_SRCS = $(addprefix $(BLUEZ_PATH)/, $(BLUEZ_SRCS))
#IMPORT_GLIB_SRC=$(addprefix $(GLIB_PATH)/,$(GLIB_SOURCE))

LOCAL_SRCS  = blue-connect.c
CROSS_LINK_COMPILE=~/Desktop/Git/Ceres/ceres_app/tools/gcc-4.8-linaro_uClibc-0.9.33.2_eabi/bin
CC = $(CROSS_LINK_COMPILE)/arm-openwrt-linux-uclibcgnueabi-gcc.bin
CFLAGS = -O0 -g

CPPFLAGS = -DHAVE_CONFIG_H

CPPFLAGS += -I$(BLUEZ_PATH)/attrib -I$(BLUEZ_PATH) -I$(BLUEZ_PATH)/lib -I$(BLUEZ_PATH)/src -I$(BLUEZ_PATH)/gdbus -I$(BLUEZ_PATH)/btio
CPPFLAGS += -I$(GLIB_PATH)/glib  -I$(GLIB_PATH)
CPPFLAGS += -L/usr/arm-linux-gnueabi/lib
LDLIBS += -pthread

all: blue-connect

blue-connect: $(LOCAL_SRCS) $(IMPORT_SRCS)
	$(CC) -L. $(CFLAGS) $(CPPFLAGS) $(LIB_NAME) -fPIC -o $@ $(GLIB_SHARE) $(THREAD_LDADD) $(LIBC) $(LOCAL_SRCS) $(IMPORT_SRCS) $(LDLIBS)

clean:
	rm -f *.o blue-connect

