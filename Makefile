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

MVN:=mvn

COMMONS_CRYPTO_OUT:=$(TARGET)/$(commons-crypto)-$(os_arch)
COMMONS_CRYPTO_OBJ:=$(addprefix $(COMMONS_CRYPTO_OUT)/,OpensslCryptoRandom.o OpensslNative.o)

ifeq ($(OS_NAME),SunOS)
  TAR:= gtar
else
  TAR:= tar
endif

NATIVE_TARGET_DIR:=$(TARGET)/classes/org/apache/commons/crypto/native/$(OS_NAME)/$(OS_ARCH)
NATIVE_DLL:=$(NATIVE_TARGET_DIR)/$(LIBNAME)

all: $(NATIVE_DLL)

$(TARGET)/jni-classes/org/apache/commons/crypto/cipher/OpensslNative.class : $(SRC)/org/apache/commons/crypto/cipher/OpensslNative.java
	@mkdir -p $(TARGET)/jni-classes
	$(JAVAC) -source 1.6 -target 1.6 -d $(TARGET)/jni-classes -sourcepath $(SRC) $<

$(TARGET)/jni-classes/org/apache/commons/crypto/random/OpensslCryptoRandomNative.class : $(SRC)/org/apache/commons/crypto/random/OpensslCryptoRandomNative.java
	@mkdir -p $(TARGET)/jni-classes
	$(JAVAC) -source 1.6 -target 1.6 -d $(TARGET)/jni-classes -sourcepath $(SRC) $<

$(TARGET)/jni-classes/org/apache/commons/crypto/cipher/OpensslNative.h: $(TARGET)/jni-classes/org/apache/commons/crypto/cipher/OpensslNative.class
	$(JAVAH) -force -classpath $(TARGET)/jni-classes -o $@ org.apache.commons.crypto.cipher.OpensslNative

$(TARGET)/jni-classes/org/apache/commons/crypto/random/OpensslCryptoRandomNative.h: $(TARGET)/jni-classes/org/apache/commons/crypto/random/OpensslCryptoRandomNative.class
	$(JAVAH) -force -classpath $(TARGET)/jni-classes -o $@ org.apache.commons.crypto.random.OpensslCryptoRandomNative

$(COMMONS_CRYPTO_OUT)/OpensslNative.o : $(SRC_NATIVE)/org/apache/commons/crypto/cipher/OpensslNative.c $(TARGET)/jni-classes/org/apache/commons/crypto/cipher/OpensslNative.h
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -c $< -o $@

$(COMMONS_CRYPTO_OUT)/OpensslCryptoRandom.o : $(SRC_NATIVE)/org/apache/commons/crypto/random/OpensslCryptoRandomNative.c $(TARGET)/jni-classes/org/apache/commons/crypto/random/OpensslCryptoRandomNative.h
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -c $< -o $@

$(COMMONS_CRYPTO_OUT)/$(LIBNAME): $(COMMONS_CRYPTO_OBJ)
	$(CXX) $(CXXFLAGS) -o $@ $+ $(LINKFLAGS)
	$(STRIP) $@

clean:
	rm -rf $(TARGET)
	rm -rf $(COMMONS_CRYPTO_OUT)

native: $(NATIVE_DLL)

$(NATIVE_DLL): $(COMMONS_CRYPTO_OUT)/$(LIBNAME)
	@mkdir -p $(@D)
	cp $< $@
	@mkdir -p $(NATIVE_TARGET_DIR)
	cp $< $(NATIVE_TARGET_DIR)/$(LIBNAME)

win32:
	$(MAKE) native CROSS_PREFIX=i686-w64-mingw32- OS_NAME=Windows OS_ARCH=x86

# for cross-compilation on Ubuntu, install the g++-mingw-w64-x86-64 package
win64:
	$(MAKE) native CROSS_PREFIX=x86_64-w64-mingw32- OS_NAME=Windows OS_ARCH=x86_64

mac32:
	$(MAKE) native OS_NAME=Mac OS_ARCH=x86

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
