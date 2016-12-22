CURL = curl
CXX = g++
SHA256SUM = shasum -a256 -p
RM = rm -f
TAR = tar
VSQL = vsql

# Optional vsql flags
VSQL_FLAGS =

# The target UDx library
LIBNAME=aesgcm.so

all: $(LIBNAME)

# Expect the Vertica SDK to be installed.
VERTICA_SDK = /opt/vertica/sdk
VERTICA_INCLUDES = $(VERTICA_SDK)/include

BUILD_REVISION = $(shell git log -1 --pretty=format:"%H" || echo "unknown")

# Optional compiler and linker arguments
CXXFLAGS = -g -O2 -Wall -Wextra -Wno-unused-parameter -Wno-unused-result
LDFLAGS =
LDLIBS =

# Necessary compiler and linker arguments
override CXXFLAGS += -fPIC
override CXXFLAGS += -I $(VERTICA_INCLUDES) -I include
override CXXFLAGS += -D HAVE_LONG_LONG_INT_64
override CXXFLAGS += -D BUILD_REVISION=\"$(BUILD_REVISION)\"
override LDFLAGS += -shared
override LDLIBS += -L lib -l:libsodium.a

# libsodium targets & variables.
LIBSODIUM_VERSION=1.0.11
LIBSODIUM_BN=libsodium-$(LIBSODIUM_VERSION)
LIBSODIUM_TAR_GZ=$(LIBSODIUM_BN).tar.gz
LIBSODIUM_URL=https://download.libsodium.org/libsodium/releases/$(LIBSODIUM_TAR_GZ)
# SHA256 hash calculated with: shasum -a256 -p $FILE | cut -d' ' -f1
LIBSODIUM_SHA256=a14549db3c49f6ae2170cbbf4664bd48ace50681045e8dbea7c8d9fb96f9c765

libsodium_deps += lib/libsodium.a
libsodium_deps += include/sodium.h

LIBSODIUM_INSTALL_DIR =

deps += $(patsubst %, $(LIBSODIUM_INSTALL_DIR)/%, $(libsodium_deps))

deps: $(deps)

$(LIBSODIUM_TAR_GZ):
	$(CURL) -o $@.tmp $(LIBSODIUM_URL)
	echo "$(LIBSODIUM_SHA256) ?$@.tmp" | $(SHA256SUM) -c -
	mv $@.tmp $@

$(libsodium_deps): $(LIBSODIUM_TAR_GZ)
	$(TAR) -xzf $<
	cd $(LIBSODIUM_BN) && ./configure --disable-pie
	make -C $(LIBSODIUM_BN) install prefix=${PWD}

src:
	mkdir -p $@

distclean: clean
	@$(RM) -r include lib
	@$(RM) $(LIBSODIUM_BN) $(LIBSODIUM_TAR_GZ) $(LIBSODIUM_TAR_GZ).tmp

objects += AESGCMDecrypt.o
objects += AESGCMEncrypt.o
objects += AESGCMFunction.o
objects += metadata.o

# Vertica requires compiling some of their SDK
objects += Vertica.o

$(objects): $(deps)

Vertica.o: $(VERTICA_INCLUDES)/Vertica.cpp
	$(CXX) $(CXXFLAGS) -c -o $@ $<

$(LIBNAME): $(objects)
	$(CXX) $(LDFLAGS) $^ $(LDLIBS) -o $@

install-ddl: install.sql | $(LIBNAME)
	$(VSQL) $(VSQL_FLAGS) -f $<

uninstall-ddl: uninstall.sql
	$(VSQL) $(VSQL_FLAGS) -f $<

test-key.hex: test-key.txt
	xxd -pu -c 32 -l 32 >$@ <$<

test: test.sql | test-key.hex $(LIBNAME)
	$(VSQL) -q -t -A $(VSQL_FLAGS) -f $< 2>&1 \
		| ./parse-tests.sh

clean-test:
	$(RM) test_key.hex

clean: clean-test
	$(RM) $(objects) $(LIBNAME)

help:
	@echo "Targets:"
	@echo "   all, $(LIBNAME)     Build the AESGCM UDx."
	@echo "   clean               Removes all build artifacts, excluding libsodium."
	@echo "   deps                Downloads and compiles libsodium, if necessary."
	@echo "                       See the LIBSODIUM_INSTALL variable below."
	@echo "   distclean           Removes all build artifacts."
	@echo "   install-ddl         Runs vsql to install the UDx to the local server."
	@echo "   test                Installs..."
	@echo "   uninstall-ddl       Runs vsql to remove the UDx from the local server."
	@echo
	@echo "Variables:"
	@echo "   LIBSODIUM_INSTALL   Path to libsodium installation (e.g. /usr/lib)."
	@echo "                       The default behavior is to download, compile, and"
	@echo "                       link against an external version ($(LIBSODIUM_VERSION))."
	@echo "   VERTICA_SDK         Path to Vertica SDK installation."
	@echo "                       ($(VERTICA_SDK))"
	@echo "   VSQL_FLAGS          Flags to pass to vsql during install-ddl,"
	@echo "                       uninstall-ddl, and test. In particular -e"
	@echo "                       (echo commands sent to server) may be useful to"
	@echo "                       diagnose errors encountered when building these"
	@echo "                       targets."

.PHONY: all clean clean-test deps distclean help install-ddl test uninstall-ddl
