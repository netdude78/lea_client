#
# Change the following variables according
# to your system environment
#
GCC_PREFIX = /usr
CC_CMD = gcc
LD_CMD = gcc
CC = $(GCC_PREFIX)/bin/$(CC_CMD)
LD = $(GCC_PREFIX)/bin/$(LD_CMD)
#PKG_DIR = /opsec
PKG_DIR = /opt/OPSEC_SDK_6.0_Linux/opsec22/pkg_rel

#
# uncomment the following setings for dynamic unixodbc support
#ODBC_CFLAGS = -DDYNAMIC_UNIXODBC -DODBCVER=0x0350 -DUSE_ODBC -I/usr/local/unixodbc/include
#ODBC_LIBS   = /usr/local/unixodbc/lib/libodbc.so /usr/local/unixodbc/lib/libodbcinst.so
#
# uncomment the following setings for static unixodbc support
#ODBC_CFLAGS = -DSTATIC_UNIXODBC -DODBCVER=0x0350 -DUSE_ODBC -I/usr/local/unixodbc/include
#ODBC_LIBS   = /usr/local/unixodbc/lib/libodbc.a /usr/local/unixodbc/lib/libodbcinst.a
#
# uncomment the following setings for dynamic iodbc support
#ODBC_CFLAGS = -DDYNAMIC_IODBC -DODBCVER=0x0350 -DUSE_ODBC -I/usr/local/include
#ODBC_LIBS   = /usr/local/lib/libiodbc.so /usr/local/lib/libiodbcinst.so
#
# uncomment the following setings for static iodbc support
#ODBC_CFLAGS = -DSTATIC_IODBC -DODBCVER=0x0350 -DUSE_ODBC -I/usr/local/include
#ODBC_LIBS   = /usr/local/lib/libiodbc.a /usr/local/lib/libiodbcinst.a

#
# you should not need to touch anything below
#
EXE_NAME = lea_client
OBJ_FILES = lea_client.o

LIB_DIR = $(PKG_DIR)/lib/release.dynamic
CPC_DIR = $(PKG_DIR)/lib/lib/dynamic/

LIBS = -lpthread -lresolv -ldl -lnsl -lopsec -lsic \
	/usr/lib/libelf.so.1 \
	-lsicauth -lcp_policy -lskey -lndb \
	-lckpssl \
	-lcpcert \
	-lcpcryptutil -lcpprng \
	-lcpbcrypt -lcpca \
	-lcpopenssl \
	-lAppUtils -lEventUtils \
	-lEncode -lComUtils \
	-lResolve -lDataStruct \
	-lOS \
	-lcpprod50

#/lib/libpam.so.0 $(CPC_DIR)/libcpc++-libc6.1-2.so.3

CFLAGS += -m32 -g -Wall -fPIC -I$(PKG_DIR)/include -DLINUX -DUNIXOS=1 -DDEBUG $(ODBC_CFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $*.c

$(EXE_NAME): $(OBJ_FILES)
	$(LD) $(CFLAGS) -L$(LIB_DIR) -o $@ $(OBJ_FILES)  $(LIBS)

clean:
	rm -f *.o $(EXE_NAME)
