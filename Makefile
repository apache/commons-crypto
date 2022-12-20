#
# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
include Makefile.common

COMMONS_CRYPTO_OUT:=$(TARGET)/$(commons-crypto)-$(os_arch)
COMMONS_CRYPTO_OBJ:=$(addprefix $(COMMONS_CRYPTO_OUT)/,OpenSslCryptoRandomNative.o OpenSslNative.o OpenSslInfoNative.o DynamicLoader.o)
COMMONS_CRYPTO_OSSL3_OBJ:=$(addprefix $(COMMONS_CRYPTO_OUT)/,OpenSslCryptoRandomNative.o OpenSsl3Native.o OpenSslInfoNative.o DynamicLoader.o)

# Shorthand for local dependencies
CRYPTO_H:=$(SRC_NATIVE)/org/apache/commons/crypto/org_apache_commons_crypto.h lib/include/config.h
CRYPTO_RANDOM_H:=$(SRC_NATIVE)/org/apache/commons/crypto/random/org_apache_commons_crypto_random.h

# Windows uses different path separators
ifeq ($(OS_NAME),Windows)
  DELTREE := CMD /C DEL /S/Q
  # The separator used for file paths
  FSEP := \\
else
  DELTREE := rm -rf
  FSEP := /
endif
# Note that some Windows commands (e.g. javah) accept both / and \ as separators
# We use the subst function to fix the paths for commands that don't accept /

NATIVE_TARGET_DIR:=$(TARGET)/classes/org/apache/commons/crypto/native/$(OS_NAME)/$(OS_ARCH)
NATIVE_DLL:=$(NATIVE_TARGET_DIR)/$(LIBNAME)
NATIVE_OSSL3_DLL:=$(NATIVE_TARGET_DIR)/$(LIBNAME_OSSL3)

all: $(NATIVE_DLL) $(NATIVE_OSSL3_DLL)

#$(TARGET)/jni-classes/org/apache/commons/crypto/cipher/OpenSslNative.h: $(TARGET)/classes/org/apache/commons/crypto/cipher/OpenSslNative.class
#	$(JAVAH) -force -classpath $(TARGET)/classes -o $@ org.apache.commons.crypto.cipher.OpenSslNative

#$(TARGET)/jni-classes/org/apache/commons/crypto/cipher/OpenSsl3Native.h: $(TARGET)/classes/org/apache/commons/crypto/cipher/OpenSsl3Native.class
#	$(JAVAH) -force -classpath $(TARGET)/classes -o $@ org.apache.commons.crypto.cipher.OpenSsl3Native

#$(TARGET)/jni-classes/org/apache/commons/crypto/random/OpenSslCryptoRandomNative.h: $(TARGET)/classes/org/apache/commons/crypto/random/OpenSslCryptoRandomNative.class
#	$(JAVAH) -force -classpath $(TARGET)/classes -o $@ org.apache.commons.crypto.random.OpenSslCryptoRandomNative

$#(TARGET)/jni-classes/org/apache/commons/crypto/OpenSslInfoNative.h: $(TARGET)/classes/org/apache/commons/crypto/OpenSslInfoNative.class
#	$(JAVAH) -force -classpath $(TARGET)/classes -o $@ org.apache.commons.crypto.OpenSslInfoNative

$(COMMONS_CRYPTO_OUT)/OpenSslNative.o : $(SRC_NATIVE)/org/apache/commons/crypto/cipher/OpenSslNative.c $(CRYPTO_H) $(TARGET)/jni-classes/org_apache_commons_crypto_cipher_OpenSslNative.h
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -c $< -o $@

$(COMMONS_CRYPTO_OUT)/OpenSsl3Native.o : $(SRC_NATIVE)/org/apache/commons/crypto/cipher/OpenSsl3Native.c $(CRYPTO_H) $(TARGET)/jni-classes/org_apache_commons_crypto_cipher_OpenSsl3Native.h
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -c $< -o $@

$(COMMONS_CRYPTO_OUT)/OpenSslCryptoRandomNative.o : $(SRC_NATIVE)/org/apache/commons/crypto/random/OpenSslCryptoRandomNative.c $(CRYPTO_H) $(CRYPTO_RANDOM_H) $(TARGET)/jni-classes/org_apache_commons_crypto_random_OpenSslCryptoRandomNative.h
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -c $< -o $@

$(COMMONS_CRYPTO_OUT)/OpenSslInfoNative.o : $(SRC_NATIVE)/org/apache/commons/crypto/OpenSslInfoNative.c $(CRYPTO_H) $(TARGET)/jni-classes/org_apache_commons_crypto_OpenSslInfoNative.h
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -DVERSION='"$(VERSION)"' -DPROJECT_NAME='"$(PROJECT_NAME)"' -I"$(TARGET)/jni-classes" -c $< -o $@

$(COMMONS_CRYPTO_OUT)/DynamicLoader.o : $(SRC_NATIVE)/org/apache/commons/crypto/DynamicLoader.c $(CRYPTO_H)
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -c $< -o $@

$(COMMONS_CRYPTO_OUT)/$(LIBNAME): $(COMMONS_CRYPTO_OBJ)
	$(CXX) $(CXXFLAGS) -o $@ $+ $(LINKFLAGS)
	$(STRIP) $@

$(COMMONS_CRYPTO_OUT)/$(LIBNAME_OSSL3): $(COMMONS_CRYPTO_OSSL3_OBJ)
	$(CXX) $(CXXFLAGS) -o $@ $+ $(LINKFLAGS)
	$(STRIP) $@

clean:
	$(DELTREE) $(subst /,$(FSEP),$(TARGET)/jni-classes)
	$(DELTREE) $(subst /,$(FSEP),$(COMMONS_CRYPTO_OUT))

native: $(NATIVE_DLL) $(NATIVE_OSSL3_DLL)

$(NATIVE_DLL): $(COMMONS_CRYPTO_OUT)/$(LIBNAME)
	@mkdir -p $(@D)
	cp $< $@

$(NATIVE_OSSL3_DLL): $(COMMONS_CRYPTO_OUT)/$(LIBNAME_OSSL3)
	@mkdir -p $(@D)
	cp $< $@

win32:
	$(MAKE) native CROSS_PREFIX=i686-w64-mingw32- OS_NAME=Windows OS_ARCH=x86

# for cross-compilation on Ubuntu, install the g++-mingw-w64-x86-64 package
win64:
	$(MAKE) native CROSS_PREFIX=x86_64-w64-mingw32- OS_NAME=Windows OS_ARCH=x86_64

mac32:
	$(MAKE) native OS_NAME=Mac OS_ARCH=x86

mac64:
	$(MAKE) native OS_NAME=Mac OS_ARCH=x86_64

linux32:
	$(MAKE) native OS_NAME=Linux OS_ARCH=x86

linux64:
	$(MAKE) native OS_NAME=Linux OS_ARCH=x86_64

freebsd64:
	$(MAKE) native OS_NAME=FreeBSD OS_ARCH=x86_64

# for cross-compilation on Ubuntu, install the g++-arm-linux-gnueabi package
linux-arm:
	$(MAKE) native CROSS_PREFIX=arm-linux-gnueabi- OS_NAME=Linux OS_ARCH=arm

# for cross-compilation on Ubuntu, install the g++-arm-linux-gnueabihf package
linux-armhf:
	$(MAKE) native CROSS_PREFIX=arm-linux-gnueabihf- OS_NAME=Linux OS_ARCH=armhf

# for cross-compilation on Ubuntu, install the g++-aarch64-linux-gnu
linux-aarch64:
	$(MAKE) native CROSS_PREFIX=aarch64-linux-gnu- OS_NAME=Linux OS_ARCH=aarch64

clean-native-linux32:
	$(MAKE) clean-native OS_NAME=Linux OS_ARCH=x86

clean-native-win32:
	$(MAKE) clean-native OS_NAME=Windows OS_ARCH=x86
