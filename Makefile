include Makefile.common

MVN:=mvn

CHIMERA_OUT:=$(TARGET)/$(chimera)-$(os_arch)
CHIMERA_OBJ:=$(addprefix $(CHIMERA_OUT)/,OpensslSecureRandom.o OpensslNative.o)

ifeq ($(OS_NAME),SunOS)
  TAR:= gtar
else
  TAR:= tar
endif

NATIVE_TARGET_DIR:=$(TARGET)/classes/com/intel/chimera/native/$(OS_NAME)/$(OS_ARCH)
NATIVE_DLL:=$(NATIVE_TARGET_DIR)/$(LIBNAME)

all: $(NATIVE_DLL)

$(TARGET)/jni-classes/com/intel/chimera/crypto/OpensslNative.class : $(SRC)/com/intel/chimera/crypto/OpensslNative.java
	@mkdir -p $(TARGET)/jni-classes
	$(JAVAC) -source 1.6 -target 1.6 -d $(TARGET)/jni-classes -sourcepath $(SRC) $<

$(TARGET)/jni-classes/com/intel/chimera/random/OpensslSecureRandomNative.class : $(SRC)/com/intel/chimera/random/OpensslSecureRandomNative.java
	@mkdir -p $(TARGET)/jni-classes
	$(JAVAC) -source 1.6 -target 1.6 -d $(TARGET)/jni-classes -sourcepath $(SRC) $<

$(TARGET)/jni-classes/com/intel/chimera/crypto/OpensslNative.h: $(TARGET)/jni-classes/com/intel/chimera/crypto/OpensslNative.class
	$(JAVAH) -force -classpath $(TARGET)/jni-classes -o $@ com.intel.chimera.crypto.OpensslNative

$(TARGET)/jni-classes/com/intel/chimera/random/OpensslSecureRandomNative.h: $(TARGET)/jni-classes/com/intel/chimera/random/OpensslSecureRandomNative.class
	$(JAVAH) -force -classpath $(TARGET)/jni-classes -o $@ com.intel.chimera.random.OpensslSecureRandomNative

$(CHIMERA_OUT)/OpensslNative.o : $(SRC_NATIVE)/com/intel/chimera/crypto/OpensslNative.c $(TARGET)/jni-classes/com/intel/chimera/crypto/OpensslNative.h
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -c $< -o $@

$(CHIMERA_OUT)/OpensslSecureRandom.o : $(SRC_NATIVE)/com/intel/chimera/random/OpensslSecureRandomNative.c $(TARGET)/jni-classes/com/intel/chimera/random/OpensslSecureRandomNative.h
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -c $< -o $@

$(CHIMERA_OUT)/$(LIBNAME): $(CHIMERA_OBJ)
	$(CXX) $(CXXFLAGS) -o $@ $+ $(LINKFLAGS)
	$(STRIP) $@

clean:
	rm -rf $(TARGET)
	rm -rf $(CHIMERA_OUT)

native: $(NATIVE_DLL)

$(NATIVE_DLL): $(CHIMERA_OUT)/$(LIBNAME)
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
