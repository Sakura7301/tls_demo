
## PATH
ROOT_PATH = $(shell pwd)
SYS = $(shell uname -s)
ARCH = $(shell uname -m)
DIST_PATH = $(ROOT_PATH)/dist

INCLUDE_PATH-y = -I $(ROOT_PATH)/include

CC      := $(CROSS_COMPILE)$(CC)
AR      := $(CROSS_COMPILE)$(AR)
CXX     := $(CROSS_COMPILE)$(CXX)


# TARGET
ifeq ($(SYS), Linux)
CFLAGS  += -fPIC
TARGET   = $(TARGET_SHARED_LIB) $(TARGET_STATIC_LIB)
RPATH    = -Wl,-rpath=$(DIST_PATH)
else
TARGET   = $(TARGET_STATIC_LIB)
endif

CFLAGS  += $(EXTRA_CFLAGS)
LDFLAGS += $(EXTRA_LDFLAGS)
CFLAGS  += $(INCLUDE_PATH-y)

CFLAGS  += -L $(ROOT_PATH)/dist
LDFLAGS += -lssl -lcrypto

####### export for compiling app #######
export CC AR CFLAGS LDFLAGS ARFLAGS
########################################

#i think you should do anything here
.PHONY: clean lib

all: lib

lib: copy_tls_lib build

copy_tls_lib:
		-mkdir $(ROOT_PATH)/dist
		-ln -s $(ROOT_PATH)/lib/libssl.so.1.1.0         $(ROOT_PATH)/dist/libssl.so
		-ln -s $(ROOT_PATH)/lib/libssl.so.1.1.0         $(ROOT_PATH)/dist/libssl.so.1.1
		-ln -s $(ROOT_PATH)/lib/libcrypto.so.1.1.0      $(ROOT_PATH)/dist/libcrypto.so
		-ln -s $(ROOT_PATH)/lib/libcrypto.so.1.1.0      $(ROOT_PATH)/dist/libcrypto.so.1.1

build:
	$(CC) -o server_bin $(CFLAGS) test_server.c $(LDFLAGS)
	$(CC) -o client_bin $(CFLAGS) test_client.c $(LDFLAGS)


clean:
	rm -rf server_bin
	rm -rf client_bin
	rm -rf $(ROOT_PATH)/dist/*


