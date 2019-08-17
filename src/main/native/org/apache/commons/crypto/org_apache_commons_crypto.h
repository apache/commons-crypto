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

/**
 * This file includes some common utilities
 * for all native code used in commons-crypto.
 */

#if !defined ORG_APACHE_COMMONS_CRYPTO_H
#define ORG_APACHE_COMMONS_CRYPTO_H

#if defined(_WIN32) || defined(_WIN64) || defined(__CYGWIN__)
#undef UNIX
#define WINDOWS
#else
#undef WINDOWS
#define UNIX
#endif

#if defined(__APPLE__)
#define MAC_OS
#endif

/* A helper macro to 'throw' a java exception. */
#define THROW(env, exception_name, message) \
  { \
    jclass ecls = (*env)->FindClass(env, exception_name); \
    if (ecls) { \
      (*env)->ThrowNew(env, ecls, message); \
      (*env)->DeleteLocalRef(env, ecls); \
    } \
  }

/* Helper macro to return if an exception is pending */
#define PASS_EXCEPTIONS(env) \
  { \
    if ((*env)->ExceptionCheck(env)) return; \
  }

#define PASS_EXCEPTIONS_GOTO(env, target) \
  { \
    if ((*env)->ExceptionCheck(env)) goto target; \
  }

#define PASS_EXCEPTIONS_RET(env, ret) \
  { \
    if ((*env)->ExceptionCheck(env)) return (ret); \
  }

/**
 * Unix definitions
 */
#ifdef UNIX
#include <config.h>
#include <dlfcn.h>
#include <jni.h>

/**
 * A helper function to dlsym a 'symbol' from a given library-handle.
 *
 * @param env jni handle to report contingencies.
 * @param handle handle to the dlopen'ed library.
 * @param symbol symbol to load.
 * @return returns the address where the symbol is loaded in memory,
 *         <code>NULL</code> on error.
 */
static __attribute__ ((unused))
void *do_dlsym(JNIEnv *env, void *handle, const char *symbol) {
  if (!env || !handle || !symbol) {
      THROW(env, "java/lang/InternalError", NULL);
      return NULL;
  }
  char *error = NULL;
  void *func_ptr = dlsym(handle, symbol);
  if ((error = dlerror()) != NULL) {
      THROW(env, "java/lang/UnsatisfiedLinkError", symbol);
      return NULL;
  }
  return func_ptr;
}

static __attribute__ ((unused))
void *do_version_dlsym(JNIEnv *env, void *handle) {
  if (!env || !handle) {
    THROW(env, "java/lang/InternalError", NULL);
      return NULL;
  }
  void *func_ptr = dlsym(handle, "OpenSSL_version_num");
  if (func_ptr == NULL) {
    func_ptr = dlsym(handle, "SSLeay");
  }
  return func_ptr;
}

/* A helper macro to dlsym the requisite dynamic symbol and bail-out on error. */
#define LOAD_DYNAMIC_SYMBOL(func_ptr, env, handle, symbol) \
  if ((func_ptr = do_dlsym(env, handle, symbol)) == NULL) { \
    return; \
  }

/* A macro to dlsym the appropriate OpenSSL version number function. */
#define LOAD_OPENSSL_VERSION_FUNCTION(func_ptr, env, handle) \
  if ((func_ptr = do_version_dlsym(env, handle)) == NULL) { \
    THROW(env, "java/lang/Error", NULL); \
  }
#endif
// Unix part end


/**
 * Windows definitions
 */
#ifdef WINDOWS

/* Force using Unicode throughout the code */
#ifndef UNICODE
#define UNICODE
#endif

/* Microsoft C Compiler does not support the C99 inline keyword */
#ifndef __cplusplus
//#define inline __inline;
#endif // _cplusplus

/* Optimization macros supported by GCC but for which there is no
   direct equivalent in the Microsoft C compiler */
#define likely(_c) (_c)
#define unlikely(_c) (_c)

/* Disable certain warnings in the native CRC32 code. */
#pragma warning(disable:4018)        // Signed/unsigned mismatch.
#pragma warning(disable:4244)        // Possible loss of data in conversion.
#pragma warning(disable:4267)        // Possible loss of data.
#pragma warning(disable:4996)        // Use of deprecated function.

#include <Windows.h>
#include <stdio.h>
#include <jni.h>

#if !defined(__MINGW32__) /* does not appear to be needed on MinGW */
#define snprintf(a, b ,c, d) _snprintf_s((a), (b), _TRUNCATE, (c), (d))
#endif

/* A helper macro to dlsym the requisite dynamic symbol and bail-out on error. */
#define LOAD_DYNAMIC_SYMBOL(func_type, func_ptr, env, handle, symbol) \
  if ((func_ptr = (func_type) do_dlsym(env, handle, symbol)) == NULL) { \
    return; \
  }

/**
 * A helper function to dynamic load a 'symbol' from a given library-handle.
 *
 * @param env jni handle to report contingencies.
 * @param handle handle to the dynamic library.
 * @param symbol symbol to load.
 * @return returns the address where the symbol is loaded in memory,
 *         <code>NULL</code> on error.
 */
static FARPROC WINAPI do_dlsym(JNIEnv *env, HMODULE handle, LPCSTR symbol) {
  DWORD dwErrorCode = ERROR_SUCCESS;
  FARPROC func_ptr = NULL;

  if (!env || !handle || !symbol) {
    THROW(env, "java/lang/InternalError", NULL);
    return NULL;
  }

  func_ptr = GetProcAddress(handle, symbol);
  if (func_ptr == NULL)
  {
    THROW(env, "java/lang/UnsatisfiedLinkError", symbol);
  }
  return func_ptr;
}

static FARPROC WINAPI do_version_dlsym(JNIEnv *env, HMODULE handle) {
  FARPROC func_ptr = NULL;
  if (!env || !handle) {
    THROW(env, "java/lang/InternalError", NULL);
    return NULL;
  }
  func_ptr = GetProcAddress(handle, "OpenSSL_version_num");
  if (func_ptr == NULL) {
    func_ptr = GetProcAddress(handle, "SSLeay");
  }
  return func_ptr;
}

/* A macro to dlsym the appropriate OpenSSL version number function. */
#define LOAD_OPENSSL_VERSION_FUNCTION(func_ptr, env, handle) \
  if ((func_ptr = (__dlsym_OpenSSL_version_num) do_version_dlsym(env, handle)) == NULL) { \
    THROW(env, "java/lang/Error", NULL); \
  }
#endif
// Windows part end


#define LOCK_CLASS(env, clazz, classname) \
  if ((*env)->MonitorEnter(env, clazz) != 0) { \
    char exception_msg[128]; \
    snprintf(exception_msg, 128, "Failed to lock %s", classname); \
    THROW(env, "java/lang/InternalError", exception_msg); \
  }

#define UNLOCK_CLASS(env, clazz, classname) \
  if ((*env)->MonitorExit(env, clazz) != 0) { \
    char exception_msg[128]; \
    snprintf(exception_msg, 128, "Failed to unlock %s", classname); \
    THROW(env, "java/lang/InternalError", exception_msg); \
  }

#define RETRY_ON_EINTR(ret, expr) do { \
  ret = expr; \
} while ((ret == -1) && (errno == EINTR));

#include "config.h"

#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/opensslv.h>

/**
 * A helper macro to convert the java 'context-handle'
 * to a EVP_CIPHER_CTX pointer.
 */
#define CONTEXT(context) ((EVP_CIPHER_CTX*)((ptrdiff_t)(context)))

/**
 * A helper macro to convert the EVP_CIPHER_CTX pointer to the
 * java 'context-handle'.
 */
#define JLONG(context) ((jlong)((ptrdiff_t)(context)))

#define KEY_LENGTH_128 16
#define KEY_LENGTH_192 24
#define KEY_LENGTH_256 32
#define IV_LENGTH 16

#define ENCRYPT_MODE 1
#define DECRYPT_MODE 0

/** Currently only support AES/CTR/NoPadding, AES/CBC/NoPadding, AES/CBC/PKCS5Padding, AES/GCM/NoPadding */
#define AES_CTR 0
#define AES_CBC 1
#define AES_GCM 2

#define NOPADDING 0
#define PKCS5PADDING 1

#define VERSION_1_0_X 0x10000000
#define VERSION_1_1_X 0x10100000

#endif

//vim: sw=2: ts=2: et
