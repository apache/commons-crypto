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

#include "org_apache_commons_crypto_random.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef UNIX
#include <pthread.h>
#include <unistd.h>
#include <sys/syscall.h>
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
#include "org_apache_commons_crypto_random_OpenSslCryptoRandomNative.h"

#ifdef UNIX
static void * (*dlsym_CRYPTO_malloc) (int, const char *, int);
static void (*dlsym_CRYPTO_free) (void *);
static ENGINE * (*dlsym_ENGINE_by_id) (const char *);
static int (*dlsym_ENGINE_init) (ENGINE *);
static int (*dlsym_ENGINE_set_default) (ENGINE *, unsigned int);
static int (*dlsym_ENGINE_finish) (ENGINE *);
static int (*dlsym_ENGINE_free) (ENGINE *);
static int (*dlsym_RAND_bytes) (unsigned char *, int);
static unsigned long (*dlsym_ERR_get_error) (void);
static unsigned long (*dlsym_OpenSSL_version_num)(void);
#endif

#ifdef WINDOWS
typedef void * (__cdecl *__dlsym_CRYPTO_malloc) (int, const char *, int);
typedef void (__cdecl *__dlsym_CRYPTO_free) (void *);
typedef ENGINE * (__cdecl *__dlsym_ENGINE_by_id) (const char *);
typedef int (__cdecl *__dlsym_ENGINE_init) (ENGINE *);
typedef int (__cdecl *__dlsym_ENGINE_set_default) (ENGINE *, unsigned int);
typedef int (__cdecl *__dlsym_ENGINE_finish) (ENGINE *);
typedef int (__cdecl *__dlsym_ENGINE_free) (ENGINE *);
typedef int (__cdecl *__dlsym_RAND_bytes) (unsigned char *, int);
typedef unsigned long (__cdecl *__dlsym_ERR_get_error) (void);
typedef unsigned long (__cdecl *__dlsym_OpenSSL_version_num) (void);
static __dlsym_CRYPTO_malloc dlsym_CRYPTO_malloc;
static __dlsym_CRYPTO_free dlsym_CRYPTO_free;
static __dlsym_ENGINE_by_id dlsym_ENGINE_by_id;
static __dlsym_ENGINE_init dlsym_ENGINE_init;
static __dlsym_ENGINE_set_default dlsym_ENGINE_set_default;
static __dlsym_ENGINE_finish dlsym_ENGINE_finish;
static __dlsym_ENGINE_free dlsym_ENGINE_free;
static __dlsym_RAND_bytes dlsym_RAND_bytes;
static __dlsym_ERR_get_error dlsym_ERR_get_error;
static __dlsym_OpenSSL_version_num dlsym_OpenSSL_version_num;
static HANDLE *lock_cs;
#endif

static ENGINE * openssl_rand_init(void);
static void openssl_rand_clean(ENGINE *eng, int clean_locks);
static int openssl_rand_bytes(unsigned char *buf, int num);

JNIEXPORT void JNICALL Java_org_apache_commons_crypto_random_OpenSslCryptoRandomNative_initSR (JNIEnv *env, jclass clazz)
{
  HMODULE openssl = open_library(env); // calls THROW and returns 0 on error

  if (!openssl) {
    return;
  }

  LOAD_DYNAMIC_SYMBOL_FALLBACK(__dlsym_OpenSSL_version_num, dlsym_OpenSSL_version_num, env, openssl, "OpenSSL_version_num", "SSLeay");
  // Reject attempt to use obsolete version
  if (dlsym_OpenSSL_version_num() < VERSION_1_1_X) {
    THROW(env, "java/lang/UnsatisfiedLinkError", "Versions below 1.1 are not supported");
    return;
  }
#ifdef UNIX
  dlerror();  // Clear any existing error
#endif
  LOAD_DYNAMIC_SYMBOL(__dlsym_CRYPTO_malloc, dlsym_CRYPTO_malloc, env, openssl, "CRYPTO_malloc");
  LOAD_DYNAMIC_SYMBOL(__dlsym_CRYPTO_free, dlsym_CRYPTO_free, env, openssl, "CRYPTO_free");
  LOAD_DYNAMIC_SYMBOL(__dlsym_ENGINE_by_id, dlsym_ENGINE_by_id, env, openssl, "ENGINE_by_id");
  LOAD_DYNAMIC_SYMBOL(__dlsym_ENGINE_init, dlsym_ENGINE_init, env, openssl, "ENGINE_init");
  LOAD_DYNAMIC_SYMBOL(__dlsym_ENGINE_set_default, dlsym_ENGINE_set_default, env, openssl, "ENGINE_set_default");
  LOAD_DYNAMIC_SYMBOL(__dlsym_ENGINE_finish, dlsym_ENGINE_finish, env, openssl, "ENGINE_finish");
  LOAD_DYNAMIC_SYMBOL(__dlsym_ENGINE_free, dlsym_ENGINE_free, env, openssl, "ENGINE_free");
  LOAD_DYNAMIC_SYMBOL(__dlsym_RAND_bytes, dlsym_RAND_bytes, env, openssl, "RAND_bytes");
  LOAD_DYNAMIC_SYMBOL(__dlsym_ERR_get_error, dlsym_ERR_get_error, env, openssl, "ERR_get_error");

  openssl_rand_init();
}

JNIEXPORT jboolean JNICALL Java_org_apache_commons_crypto_random_OpenSslCryptoRandomNative_nextRandBytes___3B
    (JNIEnv *env, jobject object, jbyteArray bytes)
{
  if (NULL == env) {
    THROW(env, "java/lang/NullPointerException", "JNIEnv cannot be null.");
	return JNI_FALSE;
  }
  if (NULL == object) {
    THROW(env, "java/lang/NullPointerException", "Object cannot be null.");
    return JNI_FALSE;
  }
  if (NULL == bytes) {
    THROW(env, "java/lang/NullPointerException", "Buffer cannot be null.");
    return JNI_FALSE;
  }
  jbyte *b = (*env)->GetByteArrayElements(env, bytes, NULL);
  if (NULL == b) {
    THROW(env, "java/lang/InternalError", "Cannot get bytes array.");
    return JNI_FALSE;
  }
  int b_len = (*env)->GetArrayLength(env, bytes);
  if (b_len < 0) {
    THROW(env, "java/lang/InternalError", "Cannot get array length.");
    return JNI_FALSE;
  }
  int ret = openssl_rand_bytes((unsigned char *)b, b_len);
  (*env)->ReleaseByteArrayElements(env, bytes, b, 0);

  if (1 != ret) {
    return JNI_FALSE;
  }
  return JNI_TRUE;
}

/**
 * If using an Intel chipset with RDRAND, the high-performance hardware
 * random number generator will be used.
 */
static ENGINE * openssl_rand_init(void)
{
  ENGINE *eng = dlsym_ENGINE_by_id("rdrand");

  int ret = -1;
  do {
    if (NULL == eng) {
      break;
    }

    int rc = dlsym_ENGINE_init(eng);
    if (0 == rc) {
      break;
    }

    rc = dlsym_ENGINE_set_default(eng, ENGINE_METHOD_RAND);
    if (0 == rc) {
      break;
    }

    ret = 0;
  } while(0);

  if (ret == -1) {
    openssl_rand_clean(eng, 0);
  }

  return eng;
}

static void openssl_rand_clean(ENGINE *eng, int clean_locks)
{
  if (NULL != eng) {
    dlsym_ENGINE_finish(eng);
    dlsym_ENGINE_free(eng);
  }
}

static int openssl_rand_bytes(unsigned char *buf, int num)
{
  return dlsym_RAND_bytes(buf, num);
}
