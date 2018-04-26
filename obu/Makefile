BASE_DIR = /home/duser/mk5
EXTRA_CFLAGS += -O -g
CFLAGS += -Wall -Werror -MD

BOARD = mk5
CROSS_COMPILE = arm-linux-gnueabihf-
ARCH = arm
CC := ccache $(CROSS_COMPILE)gcc

ifneq (,$(findstring $(BOARD),mk5))
  INSTALLDIR ?= $(BASE_DIR)/bsp/image/rootfs
  EXTRA_CFLAGS += -DBOARD_$(shell echo $(BOARD) | tr a-z A-Z) --sysroot=$(INSTALLDIR)
endif

LIB1609_SRC_DIR = $(BASE_DIR)/ieee1609/app/lib1609
LIB1609_APP_BIN = $(LIB1609_SRC_DIR)/lib1609.a

EXTRA_CFLAGS += -I$(BASE_DIR)/stack/v2x-lib/include/ \
                -I$(INSTALLDIR)/usr/include \
                -I$(BASE_DIR)/ieee1609/kernel/include \
                -I$(BASE_DIR)/ieee1609/kernel/include/linux/ieee1609/dot3 \
                -I$(BASE_DIR)/cohda/kernel/include \
                -I$(LIB1609_SRC_DIR)/include

LDFLAGS += -L$(LIB1609_SRC_DIR) -l1609 \
           -lpthread -lrt -lm

LIBS += $(LIB1609_APP_BIN)

all: client server

client: client.c
	$(CC) $(CFLAGS) $(EXTRA_CFLAGS) $(LDFLAGS) client.c -o client

server: server.c
	$(CC) $(CFLAGS) $(EXTRA_CFLAGS) $(LDFLAGS) server.c -o server

clean:
	rm -f *.d *.o
	rm -f client server

