/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "org_apache_commons_crypto.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef UNIX
#include <unistd.h>
#include <sys/types.h>
#endif

#ifdef WINDOWS
#include <windows.h>
#endif

// export the native interfaces
#ifdef JNIEXPORT
#undef JNIEXPORT
#endif
#define JNIEXPORT __attribute__((__visibility__("default")))
#include "OpenSslInfoNative.h"

#ifdef UNIX
static unsigned long (*dlsym_SSLeay) (void);
static char * (*dlsym_SSLeay_version) (int);
static unsigned long (*dlsym_OpenSSL_version_num) (void);
static char * (*dlsym_OpenSSL_version) (int);
static void *openssl_old, *openssl_new;
static int openssl_1 = 0, openssl_0 = 0;
#endif

#ifdef WINDOWS
typedef unsigned long (__cdecl *__dlsym_SSLeay) (void);
static __dlsym_SSLeay dlsym_SSLeay;
typedef char * (__cdecl *__dlsym_SSLeay_version) (int);
static __dlsym_SSLeay dlsym_SSLeay;
static __dlsym_SSLeay_version dlsym_SSLeay_version;
HMODULE openssl;
#endif

#ifdef UNIX
static void get_methods(JNIEnv *env, void *openssl)
#endif
#ifdef WINDOWS
static void get_methods(JNIEnv *env, HMODULE openssl)
#endif
{
#ifdef UNIX
  dlerror();  // Clear any existing error
  if (openssl_0) {
    LOAD_DYNAMIC_SYMBOL(dlsym_SSLeay, env, openssl_old, "SSLeay");
    LOAD_DYNAMIC_SYMBOL(dlsym_SSLeay_version, env, openssl_old, "SSLeay_version");
  }
  if (openssl_1) {
	LOAD_DYNAMIC_SYMBOL(dlsym_SSLeay, env, openssl_new, "OpenSSL_version");
	LOAD_DYNAMIC_SYMBOL(dlsym_SSLeay_version, env, openssl_new, "OpenSSL_version_num");
  }
#endif

#ifdef WINDOWS
  LOAD_DYNAMIC_SYMBOL(__dlsym_SSLeay, dlsym_SSLeay, env, openssl, "SSLeay");
  LOAD_DYNAMIC_SYMBOL(__dlsym_SSLeay_version, dlsym_SSLeay_version, env, openssl, "SSLeay_version");
#endif
}
static int load_library(JNIEnv *env)
{
    char msg[100];
#ifdef UNIX
    openssl_new = dlopen(COMMONS_CRYPTO_OPENSSL_LIBRARY_1, RTLD_LAZY | RTLD_GLOBAL);
  if (!openssl_new) {
  	snprintf(msg, sizeof(msg), "Cannot load %s (%s)!", COMMONS_CRYPTO_OPENSSL_LIBRARY_1,  \
        dlerror());
  } else {
	openssl_1 = 1;
	get_methods(env, openssl_new);
  }
  openssl_old = dlopen(COMMONS_CRYPTO_OPENSSL_LIBRARY, RTLD_LAZY | RTLD_GLOBAL);
  if (!openssl_old) {
  	snprintf(msg, sizeof(msg), "Cannot load %s (%s)!", COMMONS_CRYPTO_OPENSSL_LIBRARY,  \
        dlerror());
  } else {
	openssl_0 = 1;
	get_methods(env, openssl_old);
  }
  if (!openssl_0 && !openssl_1) {
    THROW(env, "java/lang/UnsatisfiedLinkError", msg);
    return 0;
  }
#endif
#ifdef WINDOWS
  openssl = LoadLibrary(TEXT(COMMONS_CRYPTO_OPENSSL_LIBRARY));
  if (!openssl) {
    snprintf(msg, sizeof(msg), "Cannot load %s (%d)!", COMMONS_CRYPTO_OPENSSL_LIBRARY,  \
  	  GetLastError());
    THROW(env, "java/lang/UnsatisfiedLinkError", msg);
    return 0;
  } else {
  	 get_methods(env, openssl);
  }
#endif

  return 1;
}

JNIEXPORT jstring JNICALL Java_org_apache_commons_crypto_OpenSslInfoNative_SSLeayVersion
    (JNIEnv *env, jclass clazz, jint type)
{
	jstring answer = NULL;
    if (!load_library(env)) {
        return NULL;
    }
#ifdef UNIX
	if (openssl_0) {
    	answer = (*env)->NewStringUTF(env,dlsym_SSLeay_version(type));
	}
	if (openssl_1) {
		answer = (*env)->NewStringUTF(env,dlsym_OpenSSL_version(type));
	}
#endif
#ifdef WINDOWS
	answer = (*env)->NewStringUTF(env,dlsym_SSLeay_version(type));
#endif
	return answer;
}

JNIEXPORT jlong JNICALL Java_org_apache_commons_crypto_OpenSslInfoNative_SSLeay
    (JNIEnv *env, jobject object)
{
    if (!load_library(env)) {
        return 0;
    }
	if (openssl_1)
		return dlsym_OpenSSL_version_num();
	else
    	return dlsym_SSLeay();
}

JNIEXPORT jstring JNICALL Java_org_apache_commons_crypto_OpenSslInfoNative_NativeVersion
    (JNIEnv *env, jobject object)
{
    return (*env)->NewStringUTF(env, VERSION);
}

JNIEXPORT jstring JNICALL Java_org_apache_commons_crypto_OpenSslInfoNative_NativeTimeStamp
    (JNIEnv *env, jobject object)
{
    return (*env)->NewStringUTF(env, __DATE__);
}

JNIEXPORT jstring JNICALL Java_org_apache_commons_crypto_OpenSslInfoNative_NativeName
    (JNIEnv *env, jobject object)
{
    return (*env)->NewStringUTF(env, PROJECT_NAME);
}
