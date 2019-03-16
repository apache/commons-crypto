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
#include "OpenSslCryptoRandomNative.h"

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
static void *openssl;
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
static __dlsym_CRYPTO_malloc dlsym_CRYPTO_malloc;
static __dlsym_CRYPTO_free dlsym_CRYPTO_free;
static __dlsym_ENGINE_by_id dlsym_ENGINE_by_id;
static __dlsym_ENGINE_init dlsym_ENGINE_init;
static __dlsym_ENGINE_set_default dlsym_ENGINE_set_default;
static __dlsym_ENGINE_finish dlsym_ENGINE_finish;
static __dlsym_ENGINE_free dlsym_ENGINE_free;
static __dlsym_RAND_bytes dlsym_RAND_bytes;
static __dlsym_ERR_get_error dlsym_ERR_get_error;
#endif

static ENGINE * openssl_rand_init(JNIEnv *env);
static void openssl_rand_clean(JNIEnv *env, ENGINE *eng, int clean_locks);
static int openssl_rand_bytes(unsigned char *buf, int num);
static void pthreads_locking_callback(int mode, int type, char *file, int line);
static unsigned long pthreads_thread_id(void);
//static pthread_mutex_t *lock_cs;

JNIEXPORT void JNICALL Java_org_apache_commons_crypto_random_OpenSslCryptoRandomNative_initSR
    (JNIEnv *env, jclass clazz)
{
  char msg[1000];
#ifdef UNIX
  openssl = dlopen(COMMONS_CRYPTO_OPENSSL_LIBRARY, RTLD_LAZY | RTLD_GLOBAL);
#endif

#ifdef WINDOWS
  HMODULE openssl = LoadLibrary(TEXT(COMMONS_CRYPTO_OPENSSL_LIBRARY));
#endif

  if (!openssl) {
#ifdef UNIX
    snprintf(msg, sizeof(msg), "Cannot load %s (%s)!", COMMONS_CRYPTO_OPENSSL_LIBRARY,  \
        dlerror());
#endif
#ifdef WINDOWS
    snprintf(msg, sizeof(msg), "Cannot load %s (%d)!", COMMONS_CRYPTO_OPENSSL_LIBRARY,  \
        GetLastError());
#endif
    THROW(env, "java/lang/UnsatisfiedLinkError", msg);
    return;
  }

#ifdef UNIX
  dlerror();  // Clear any existing error
  LOAD_DYNAMIC_SYMBOL(dlsym_CRYPTO_malloc, env, openssl, "CRYPTO_malloc");
  LOAD_DYNAMIC_SYMBOL(dlsym_CRYPTO_free, env, openssl, "CRYPTO_free");
  LOAD_DYNAMIC_SYMBOL(dlsym_ENGINE_by_id, env, openssl, "ENGINE_by_id");
  LOAD_DYNAMIC_SYMBOL(dlsym_ENGINE_init, env, openssl, "ENGINE_init");
  LOAD_DYNAMIC_SYMBOL(dlsym_ENGINE_set_default, env,  \
                      openssl, "ENGINE_set_default");
  LOAD_DYNAMIC_SYMBOL(dlsym_ENGINE_finish, env, openssl, "ENGINE_finish");
  LOAD_DYNAMIC_SYMBOL(dlsym_ENGINE_free, env, openssl, "ENGINE_free");
  LOAD_DYNAMIC_SYMBOL(dlsym_RAND_bytes, env, openssl, "RAND_bytes");
  LOAD_DYNAMIC_SYMBOL(dlsym_ERR_get_error, env, openssl, "ERR_get_error");
  LOAD_OPENSSL_VERSION_FUNCTION(dlsym_OpenSSL_version_num, env, openssl);
#endif

#ifdef WINDOWS
  LOAD_DYNAMIC_SYMBOL(__dlsym_CRYPTO_malloc, dlsym_CRYPTO_malloc,  \
                      env, openssl, "CRYPTO_malloc");
  LOAD_DYNAMIC_SYMBOL(__dlsym_CRYPTO_free, dlsym_CRYPTO_free,  \
                      env, openssl, "CRYPTO_free");
  LOAD_DYNAMIC_SYMBOL(__dlsym_ENGINE_by_id, dlsym_ENGINE_by_id,  \
                      env, openssl, "ENGINE_by_id");
  LOAD_DYNAMIC_SYMBOL(__dlsym_ENGINE_init, dlsym_ENGINE_init,  \
                      env, openssl, "ENGINE_init");
  LOAD_DYNAMIC_SYMBOL(__dlsym_ENGINE_set_default, dlsym_ENGINE_set_default,  \
                      env, openssl, "ENGINE_set_default");
  LOAD_DYNAMIC_SYMBOL(__dlsym_ENGINE_finish, dlsym_ENGINE_finish,  \
                      env, openssl, "ENGINE_finish");
  LOAD_DYNAMIC_SYMBOL(__dlsym_ENGINE_free, dlsym_ENGINE_free,  \
                      env, openssl, "ENGINE_free");
  LOAD_DYNAMIC_SYMBOL(__dlsym_RAND_bytes, dlsym_RAND_bytes,  \
                      env, openssl, "RAND_bytes");
  LOAD_DYNAMIC_SYMBOL(__dlsym_ERR_get_error, dlsym_ERR_get_error,  \
                      env, openssl, "ERR_get_error");
#endif

  openssl_rand_init(env);
}

JNIEXPORT jboolean JNICALL Java_org_apache_commons_crypto_random_OpenSslCryptoRandomNative_nextRandBytes___3B
    (JNIEnv *env, jobject object, jbyteArray bytes)
{
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
  int ret = openssl_rand_bytes((unsigned char *)b, b_len);
  (*env)->ReleaseByteArrayElements(env, bytes, b, 0);

  if (1 != ret) {
    return JNI_FALSE;
  }
  return JNI_TRUE;
}

/**
 * To ensure thread safety for random number generators, we need to call
 * CRYPTO_set_locking_callback.
 * http://wiki.openssl.org/index.php/Random_Numbers
 * Example: crypto/threads/mttest.c
 */

#ifdef WINDOWS
static void windows_locking_callback(int mode, int type, char *file, int line);
static HANDLE *lock_cs;

static void locks_setup(void)
{
  int i;
  lock_cs = dlsym_CRYPTO_malloc(dlsym_CRYPTO_num_locks() * sizeof(HANDLE),  \
      __FILE__, __LINE__);

  for (i = 0; i < dlsym_CRYPTO_num_locks(); i++) {
    lock_cs[i] = CreateMutex(NULL, FALSE, NULL);
  }
  dlsym_CRYPTO_set_locking_callback((void (*)(int, int, char *, int))  \
      windows_locking_callback);
  /* id callback defined */
}

static void locks_cleanup(void)
{
  int i;
  dlsym_CRYPTO_set_locking_callback(NULL);

  for (i = 0; i < dlsym_CRYPTO_num_locks(); i++) {
    CloseHandle(lock_cs[i]);
  }
  dlsym_CRYPTO_free(lock_cs);
}

static void windows_locking_callback(int mode, int type, char *file, int line)
{
  UNUSED(file), UNUSED(line);

  if (mode & CRYPTO_LOCK) {
    WaitForSingleObject(lock_cs[type], INFINITE);
  } else {
    ReleaseMutex(lock_cs[type]);
  }
}
#endif /* WINDOWS */

#ifdef UNIX
static void pthreads_locking_callback(int mode, int type, char *file, int line);
static unsigned long pthreads_thread_id(void);
static pthread_mutex_t *lock_cs;

static void locks_setup(JNIEnv *env)
{
  int i;
  static int (*dlsym_CRYPTO_num_locks) (void);
  dlsym_CRYPTO_num_locks = do_dlsym(env, openssl, "CRYPTO_num_locks");
  lock_cs = dlsym_CRYPTO_malloc(dlsym_CRYPTO_num_locks() *  \
      sizeof(pthread_mutex_t), __FILE__, __LINE__);

  for (i = 0; i < dlsym_CRYPTO_num_locks(); i++) {
    pthread_mutex_init(&(lock_cs[i]), NULL);
  }

  static void (*dlsym_CRYPTO_set_id_callback) (unsigned long (*)());
  dlsym_CRYPTO_set_id_callback = do_dlsym(env, openssl, "CRYPTO_set_id_callback");
  static void (*dlsym_CRYPTO_set_locking_callback) (void (*)());
  dlsym_CRYPTO_set_locking_callback = do_dlsym(env, openssl, "CRYPTO_set_locking_callback");

  dlsym_CRYPTO_set_id_callback((unsigned long (*)())pthreads_thread_id);
  dlsym_CRYPTO_set_locking_callback((void (*)())pthreads_locking_callback);
}

static void locks_cleanup(JNIEnv *env)
{
  int i;
  static int (*dlsym_CRYPTO_num_locks) (void);
  dlsym_CRYPTO_num_locks = do_dlsym(env, openssl, "CRYPTO_num_locks");
  static void (*dlsym_CRYPTO_set_locking_callback) (void (*)());
  dlsym_CRYPTO_set_locking_callback = do_dlsym(env, openssl, "CRYPTO_set_locking_callback");
  dlsym_CRYPTO_set_locking_callback(NULL);

  for (i = 0; i < dlsym_CRYPTO_num_locks(); i++) {
    pthread_mutex_destroy(&(lock_cs[i]));
  }

  dlsym_CRYPTO_free(lock_cs);
}

static void pthreads_locking_callback(int mode, int type, char *file, int line)
{
  UNUSED(file), UNUSED(line);

  if (mode & CRYPTO_LOCK) {
    pthread_mutex_lock(&(lock_cs[type]));
  } else {
    pthread_mutex_unlock(&(lock_cs[type]));
  }
}

static unsigned long pthreads_thread_id(void)
{
  return (unsigned long)syscall(SYS_gettid);
}

#endif /* UNIX */

/**
 * If using an Intel chipset with RDRAND, the high-performance hardware
 * random number generator will be used.
 */
static ENGINE * openssl_rand_init(JNIEnv *env)
{
  if (dlsym_OpenSSL_version_num() < VERSION_1_1_X) {
    locks_setup(env);
    static void (*dlsym_ENGINE_load_rdrand) (void);
    dlsym_ENGINE_load_rdrand = do_dlsym(env, openssl, "ENGINE_load_rdrand");
    dlsym_ENGINE_load_rdrand();
  }

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
    openssl_rand_clean(env, eng, 0);
  }

  return eng;
}

static void openssl_rand_clean(JNIEnv *env, ENGINE *eng, int clean_locks)
{
  if (NULL != eng) {
    dlsym_ENGINE_finish(eng);
    dlsym_ENGINE_free(eng);
  }

  if (dlsym_OpenSSL_version_num() < VERSION_1_1_X) {
    static void (*dlsym_ENGINE_cleanup) (void);
    if((dlsym_ENGINE_cleanup = do_dlsym(env, openssl, "ENGINE_cleanup")) == NULL) {
	THROW(env, "java/lang/UnsatisfiedLinkError", "ENGINE_cleanup");
    }
    dlsym_ENGINE_cleanup();
    if (clean_locks) {
      locks_cleanup(env);
    }
  }
}

static int openssl_rand_bytes(unsigned char *buf, int num)
{
  return dlsym_RAND_bytes(buf, num);
}
