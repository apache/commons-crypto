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

// export the native interfaces
#ifdef JNIEXPORT
#undef JNIEXPORT
#endif
#define JNIEXPORT __attribute__((__visibility__("default")))
#include "OpenSslNative.h"

#ifdef UNIX
static EVP_CIPHER_CTX * (*dlsym_EVP_CIPHER_CTX_new)(void);
static void (*dlsym_EVP_CIPHER_CTX_free)(EVP_CIPHER_CTX *);
static int (*dlsym_EVP_CIPHER_CTX_cleanup)(EVP_CIPHER_CTX *);
static void (*dlsym_EVP_CIPHER_CTX_init)(EVP_CIPHER_CTX *);
static int (*dlsym_EVP_CIPHER_CTX_set_padding)(EVP_CIPHER_CTX *, int);
static int (*dlsym_EVP_CIPHER_CTX_ctrl)(EVP_CIPHER_CTX *, int, int, void *);
static int (*dlsym_EVP_CipherInit_ex)(EVP_CIPHER_CTX *, const EVP_CIPHER *,  \
           ENGINE *, const unsigned char *, const unsigned char *, int);
static int (*dlsym_EVP_CipherUpdate)(EVP_CIPHER_CTX *, unsigned char *,  \
           int *, const unsigned char *, int);
static int (*dlsym_EVP_CipherFinal_ex)(EVP_CIPHER_CTX *, unsigned char *, int *);
static EVP_CIPHER * (*dlsym_EVP_aes_256_ctr)(void);
static EVP_CIPHER * (*dlsym_EVP_aes_192_ctr)(void);
static EVP_CIPHER * (*dlsym_EVP_aes_128_ctr)(void);
static EVP_CIPHER * (*dlsym_EVP_aes_256_cbc)(void);
static EVP_CIPHER * (*dlsym_EVP_aes_192_cbc)(void);
static EVP_CIPHER * (*dlsym_EVP_aes_128_cbc)(void);
static EVP_CIPHER * (*dlsym_EVP_aes_256_gcm)(void);
static EVP_CIPHER * (*dlsym_EVP_aes_192_gcm)(void);
static EVP_CIPHER * (*dlsym_EVP_aes_128_gcm)(void);
#endif

#ifdef WINDOWS
typedef EVP_CIPHER_CTX * (__cdecl *__dlsym_EVP_CIPHER_CTX_new)(void);
typedef void (__cdecl *__dlsym_EVP_CIPHER_CTX_free)(EVP_CIPHER_CTX *);
typedef int (__cdecl *__dlsym_EVP_CIPHER_CTX_cleanup)(EVP_CIPHER_CTX *);
typedef void (__cdecl *__dlsym_EVP_CIPHER_CTX_init)(EVP_CIPHER_CTX *);
typedef int (__cdecl *__dlsym_EVP_CIPHER_CTX_set_padding)(EVP_CIPHER_CTX *, int);
typedef int (__cdecl *__dlsym_EVP_CIPHER_CTX_ctrl)(EVP_CIPHER_CTX *, int, int, void *);
typedef int (__cdecl *__dlsym_EVP_CipherInit_ex)(EVP_CIPHER_CTX *,  \
             const EVP_CIPHER *, ENGINE *, const unsigned char *,  \
             const unsigned char *, int);
typedef int (__cdecl *__dlsym_EVP_CipherUpdate)(EVP_CIPHER_CTX *,  \
             unsigned char *, int *, const unsigned char *, int);
typedef int (__cdecl *__dlsym_EVP_CipherFinal_ex)(EVP_CIPHER_CTX *,  \
             unsigned char *, int *);
typedef EVP_CIPHER * (__cdecl *__dlsym_EVP_aes_256_ctr)(void);
typedef EVP_CIPHER * (__cdecl *__dlsym_EVP_aes_192_ctr)(void);
typedef EVP_CIPHER * (__cdecl *__dlsym_EVP_aes_128_ctr)(void);
typedef EVP_CIPHER * (__cdecl *__dlsym_EVP_aes_256_cbc)(void);
typedef EVP_CIPHER * (__cdecl *__dlsym_EVP_aes_192_cbc)(void);
typedef EVP_CIPHER * (__cdecl *__dlsym_EVP_aes_128_cbc)(void);
typedef EVP_CIPHER * (__cdecl *__dlsym_EVP_aes_256_gcm)(void);
typedef EVP_CIPHER * (__cdecl *__dlsym_EVP_aes_192_gcm)(void);
typedef EVP_CIPHER * (__cdecl *__dlsym_EVP_aes_128_gcm)(void);
static __dlsym_EVP_CIPHER_CTX_new dlsym_EVP_CIPHER_CTX_new;
static __dlsym_EVP_CIPHER_CTX_free dlsym_EVP_CIPHER_CTX_free;
static __dlsym_EVP_CIPHER_CTX_cleanup dlsym_EVP_CIPHER_CTX_cleanup;
static __dlsym_EVP_CIPHER_CTX_init dlsym_EVP_CIPHER_CTX_init;
static __dlsym_EVP_CIPHER_CTX_set_padding dlsym_EVP_CIPHER_CTX_set_padding;
static __dlsym_EVP_CIPHER_CTX_ctrl dlsym_EVP_CIPHER_CTX_ctrl;
static __dlsym_EVP_CipherInit_ex dlsym_EVP_CipherInit_ex;
static __dlsym_EVP_CipherUpdate dlsym_EVP_CipherUpdate;
static __dlsym_EVP_CipherFinal_ex dlsym_EVP_CipherFinal_ex;
static __dlsym_EVP_aes_256_ctr dlsym_EVP_aes_256_ctr;
static __dlsym_EVP_aes_192_ctr dlsym_EVP_aes_192_ctr;
static __dlsym_EVP_aes_128_ctr dlsym_EVP_aes_128_ctr;
static __dlsym_EVP_aes_256_cbc dlsym_EVP_aes_256_cbc;
static __dlsym_EVP_aes_192_cbc dlsym_EVP_aes_192_cbc;
static __dlsym_EVP_aes_128_cbc dlsym_EVP_aes_128_cbc;
static __dlsym_EVP_aes_256_gcm dlsym_EVP_aes_256_gcm;
static __dlsym_EVP_aes_192_gcm dlsym_EVP_aes_192_gcm;
static __dlsym_EVP_aes_128_gcm dlsym_EVP_aes_128_gcm;
#endif

#ifdef UNIX
static void loadAes(JNIEnv *env, void *openssl)
#endif

#ifdef WINDOWS
static void loadAes(JNIEnv *env, HMODULE openssl)
#endif
{
#ifdef UNIX
  LOAD_DYNAMIC_SYMBOL(dlsym_EVP_aes_256_ctr, env, openssl, "EVP_aes_256_ctr");
  LOAD_DYNAMIC_SYMBOL(dlsym_EVP_aes_192_ctr, env, openssl, "EVP_aes_192_ctr");
  LOAD_DYNAMIC_SYMBOL(dlsym_EVP_aes_128_ctr, env, openssl, "EVP_aes_128_ctr");
  LOAD_DYNAMIC_SYMBOL(dlsym_EVP_aes_256_cbc, env, openssl, "EVP_aes_256_cbc");
  LOAD_DYNAMIC_SYMBOL(dlsym_EVP_aes_192_cbc, env, openssl, "EVP_aes_192_cbc");
  LOAD_DYNAMIC_SYMBOL(dlsym_EVP_aes_128_cbc, env, openssl, "EVP_aes_128_cbc");
  LOAD_DYNAMIC_SYMBOL(dlsym_EVP_aes_256_gcm, env, openssl, "EVP_aes_256_gcm");
  LOAD_DYNAMIC_SYMBOL(dlsym_EVP_aes_192_gcm, env, openssl, "EVP_aes_192_gcm");
  LOAD_DYNAMIC_SYMBOL(dlsym_EVP_aes_128_gcm, env, openssl, "EVP_aes_128_gcm");
#endif

#ifdef WINDOWS
  LOAD_DYNAMIC_SYMBOL(__dlsym_EVP_aes_256_ctr, dlsym_EVP_aes_256_ctr,  \
                      env, openssl, "EVP_aes_256_ctr");
  LOAD_DYNAMIC_SYMBOL(__dlsym_EVP_aes_192_ctr, dlsym_EVP_aes_192_ctr,  \
                      env, openssl, "EVP_aes_192_ctr");
  LOAD_DYNAMIC_SYMBOL(__dlsym_EVP_aes_128_ctr, dlsym_EVP_aes_128_ctr,  \
                      env, openssl, "EVP_aes_128_ctr");
  LOAD_DYNAMIC_SYMBOL(__dlsym_EVP_aes_256_cbc, dlsym_EVP_aes_256_cbc,  \
                      env, openssl, "EVP_aes_256_cbc");
  LOAD_DYNAMIC_SYMBOL(__dlsym_EVP_aes_192_cbc, dlsym_EVP_aes_192_cbc,  \
                      env, openssl, "EVP_aes_192_cbc");
  LOAD_DYNAMIC_SYMBOL(__dlsym_EVP_aes_128_cbc, dlsym_EVP_aes_128_cbc,  \
                      env, openssl, "EVP_aes_128_cbc");
  LOAD_DYNAMIC_SYMBOL(__dlsym_EVP_aes_256_gcm, dlsym_EVP_aes_256_gcm,  \
                      env, openssl, "EVP_aes_256_gcm");
  LOAD_DYNAMIC_SYMBOL(__dlsym_EVP_aes_192_gcm, dlsym_EVP_aes_192_gcm,  \
                      env, openssl, "EVP_aes_192_gcm");
  LOAD_DYNAMIC_SYMBOL(__dlsym_EVP_aes_128_gcm, dlsym_EVP_aes_128_gcm,  \
                      env, openssl, "EVP_aes_128_gcm");
#endif
}

JNIEXPORT void JNICALL Java_org_apache_commons_crypto_cipher_OpenSslNative_initIDs
    (JNIEnv *env, jclass clazz)
{
  char msg[1000];
#ifdef UNIX
  void *openssl = dlopen(COMMONS_CRYPTO_OPENSSL_LIBRARY, RTLD_LAZY | RTLD_GLOBAL);
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
  LOAD_DYNAMIC_SYMBOL(dlsym_EVP_CIPHER_CTX_new, env, openssl,  \
                      "EVP_CIPHER_CTX_new");
  LOAD_DYNAMIC_SYMBOL(dlsym_EVP_CIPHER_CTX_free, env, openssl,  \
                      "EVP_CIPHER_CTX_free");
  LOAD_DYNAMIC_SYMBOL(dlsym_EVP_CIPHER_CTX_cleanup, env, openssl,  \
                      "EVP_CIPHER_CTX_cleanup");
  LOAD_DYNAMIC_SYMBOL(dlsym_EVP_CIPHER_CTX_init, env, openssl,  \
                      "EVP_CIPHER_CTX_init");
  LOAD_DYNAMIC_SYMBOL(dlsym_EVP_CIPHER_CTX_set_padding, env, openssl,  \
                      "EVP_CIPHER_CTX_set_padding");
  LOAD_DYNAMIC_SYMBOL(dlsym_EVP_CIPHER_CTX_ctrl, env, openssl,  \
                      "EVP_CIPHER_CTX_ctrl");
  LOAD_DYNAMIC_SYMBOL(dlsym_EVP_CipherInit_ex, env, openssl,  \
                      "EVP_CipherInit_ex");
  LOAD_DYNAMIC_SYMBOL(dlsym_EVP_CipherUpdate, env, openssl,  \
                      "EVP_CipherUpdate");
  LOAD_DYNAMIC_SYMBOL(dlsym_EVP_CipherFinal_ex, env, openssl,  \
                      "EVP_CipherFinal_ex");
#endif

#ifdef WINDOWS
  LOAD_DYNAMIC_SYMBOL(__dlsym_EVP_CIPHER_CTX_new, dlsym_EVP_CIPHER_CTX_new,  \
                      env, openssl, "EVP_CIPHER_CTX_new");
  LOAD_DYNAMIC_SYMBOL(__dlsym_EVP_CIPHER_CTX_free, dlsym_EVP_CIPHER_CTX_free,  \
                      env, openssl, "EVP_CIPHER_CTX_free");
  LOAD_DYNAMIC_SYMBOL(__dlsym_EVP_CIPHER_CTX_cleanup,  \
                      dlsym_EVP_CIPHER_CTX_cleanup, env,
                      openssl, "EVP_CIPHER_CTX_cleanup");
  LOAD_DYNAMIC_SYMBOL(__dlsym_EVP_CIPHER_CTX_init, dlsym_EVP_CIPHER_CTX_init,  \
                      env, openssl, "EVP_CIPHER_CTX_init");
  LOAD_DYNAMIC_SYMBOL(__dlsym_EVP_CIPHER_CTX_set_padding,  \
                      dlsym_EVP_CIPHER_CTX_set_padding, env,  \
                      openssl, "EVP_CIPHER_CTX_set_padding");
  LOAD_DYNAMIC_SYMBOL(__dlsym_EVP_CipherInit_ex, dlsym_EVP_CipherInit_ex,  \
                      env, openssl, "EVP_CipherInit_ex");
  LOAD_DYNAMIC_SYMBOL(__dlsym_EVP_CipherUpdate, dlsym_EVP_CipherUpdate,  \
                      env, openssl, "EVP_CipherUpdate");
  LOAD_DYNAMIC_SYMBOL(__dlsym_EVP_CipherFinal_ex, dlsym_EVP_CipherFinal_ex,  \
                      env, openssl, "EVP_CipherFinal_ex");
#endif

  loadAes(env, openssl);
  jthrowable jthr = (*env)->ExceptionOccurred(env);
  if (jthr) {
    (*env)->DeleteLocalRef(env, jthr);
    THROW(env, "java/lang/UnsatisfiedLinkError",  \
        "Cannot find AES-CTR support, is your version of Openssl new enough?");
    return;
  }
}

JNIEXPORT jlong JNICALL Java_org_apache_commons_crypto_cipher_OpenSslNative_initContext
    (JNIEnv *env, jclass clazz, jint alg, jint padding)
{
  if (alg != AES_CTR && alg != AES_CBC && alg != AES_GCM) {
    THROW(env, "java/security/NoSuchAlgorithmException", NULL);
    return (jlong)0;
  }
  if (!(alg == AES_CTR && padding == NOPADDING)
      && !(alg == AES_CBC && (padding == NOPADDING|| padding == PKCS5PADDING))
      && !(alg == AES_GCM && padding == NOPADDING)) {
    THROW(env, "javax/crypto/NoSuchPaddingException", NULL);
    return (jlong)0;
  }

  if (dlsym_EVP_aes_256_ctr == NULL ||
        dlsym_EVP_aes_192_ctr == NULL || dlsym_EVP_aes_128_ctr == NULL) {
    THROW(env, "java/security/NoSuchAlgorithmException",  \
        "Doesn't support AES CTR.");
    return (jlong)0;
  }

  if (dlsym_EVP_aes_256_cbc == NULL ||
        dlsym_EVP_aes_192_cbc == NULL || dlsym_EVP_aes_128_cbc == NULL) {
    THROW(env, "java/security/NoSuchAlgorithmException",  \
        "Doesn't support AES CBC.");
    return (jlong)0;
  }

  if (dlsym_EVP_aes_256_gcm == NULL ||
    dlsym_EVP_aes_192_gcm == NULL || dlsym_EVP_aes_128_gcm == NULL) {
    THROW(env, "java/security/NoSuchAlgorithmException",  \
       "Doesn't support AES GCM.");
    return (jlong)0;
  }

  // Create and initialize a EVP_CIPHER_CTX
  EVP_CIPHER_CTX *context = dlsym_EVP_CIPHER_CTX_new();
  if (!context) {
    THROW(env, "java/lang/OutOfMemoryError", NULL);
    return (jlong)0;
  }

  return JLONG(context);
}

// Only supports AES-CTR and AES-CBC currently
static EVP_CIPHER * getEvpCipher(int alg, int keyLen)
{
  EVP_CIPHER *cipher = NULL;
  if (alg == AES_CTR) {
    if (keyLen == KEY_LENGTH_256) {
      cipher = dlsym_EVP_aes_256_ctr();
    } else if (keyLen == KEY_LENGTH_192) {
      cipher = dlsym_EVP_aes_192_ctr();
    } else if (keyLen == KEY_LENGTH_128) {
      cipher = dlsym_EVP_aes_128_ctr();
    }
  } else if (alg == AES_CBC) {
    if (keyLen == KEY_LENGTH_256) {
      cipher = dlsym_EVP_aes_256_cbc();
    } else if (keyLen == KEY_LENGTH_192) {
      cipher = dlsym_EVP_aes_192_cbc();
    } else if (keyLen == KEY_LENGTH_128) {
      cipher = dlsym_EVP_aes_128_cbc();
    }
  } else if (alg == AES_GCM) {
    if (keyLen == KEY_LENGTH_256) {
      cipher = dlsym_EVP_aes_256_gcm();
    } else if (keyLen == KEY_LENGTH_192) {
      cipher = dlsym_EVP_aes_192_gcm();
    } else if (keyLen == KEY_LENGTH_128) {
      cipher = dlsym_EVP_aes_128_gcm();
    }
  }
  return cipher;
}

JNIEXPORT jlong JNICALL Java_org_apache_commons_crypto_cipher_OpenSslNative_init
    (JNIEnv *env, jclass clazz, jlong ctx, jint mode, jint alg, jint padding,
    jbyteArray key, jbyteArray iv)
{
  jlong result = 0L;
  EVP_CIPHER_CTX *context = CONTEXT(ctx);

  jbyte *jKey = NULL;
  jbyte *jIv  = NULL;
  int jKeyLen = (*env)->GetArrayLength(env, key);
  int jIvLen = (*env)->GetArrayLength(env, iv);
  if (jKeyLen != KEY_LENGTH_128 && jKeyLen != KEY_LENGTH_192
        && jKeyLen != KEY_LENGTH_256) {
    char str[64] = {0};
    snprintf(str, sizeof(str), "Invalid AES key length: %d bytes", jKeyLen);
    THROW(env, "java/security/InvalidKeyException", str);
    goto cleanup;
  }
  if ((alg != AES_GCM) && (jIvLen != IV_LENGTH)) {
    THROW(env, "java/security/InvalidAlgorithmParameterException", "Wrong IV length: must be 16 bytes long");
    goto cleanup;
  }

  if (context == 0) {
    // Create and initialize a EVP_CIPHER_CTX
    context = dlsym_EVP_CIPHER_CTX_new();
    if (!context) {
      THROW(env, "java/lang/OutOfMemoryError", NULL);
      return (jlong)0;
    }
  }

  jKey = (*env)->GetByteArrayElements(env, key, NULL);
  if (jKey == NULL) {
    THROW(env, "java/lang/InternalError", "Cannot get bytes array for key.");
    goto cleanup;
  }
  jIv = (*env)->GetByteArrayElements(env, iv, NULL);
  if (jIv == NULL) {
    THROW(env, "java/lang/InternalError", "Cannot get bytes array for iv.");
    goto cleanup;
  }

  if (!(alg == AES_CTR || alg == AES_CBC || alg == AES_GCM)) {
    THROW(env, "java/security/NoSuchAlgorithmException", "The algorithm is not supported.");
    goto cleanup;
  }

  // initialize cipher & mode
  int rc = dlsym_EVP_CipherInit_ex(context, getEvpCipher(alg, jKeyLen),  \
      NULL, NULL, NULL, mode == ENCRYPT_MODE);
  if (rc == 0) {
    THROW(env, "java/lang/InternalError", "Error in EVP_CipherInit_ex.");
    goto cleanup;
  }

  // Set IV length if default 12 bytes (96 bits) is not appropriate
  // Note: set IV length after cipher is initialized, before iv is initialized.
  if (alg == AES_GCM) {
    rc = dlsym_EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_SET_IVLEN, jIvLen, NULL);
  }
  rc = dlsym_EVP_CipherInit_ex(context, NULL, NULL, \
         (unsigned char *)jKey, (unsigned char *)jIv, mode == ENCRYPT_MODE);
  if (rc == 0) {
    THROW(env, "java/lang/InternalError", "Error in EVP_CipherInit_ex.");
    goto cleanup;
  }

  if (padding == NOPADDING) {
    dlsym_EVP_CIPHER_CTX_set_padding(context, 0);
  } else if (padding == PKCS5PADDING) {
    dlsym_EVP_CIPHER_CTX_set_padding(context, 1);
  }

  // everything is OK,
  result = JLONG(context);

cleanup:
  if (result == 0 && context != NULL) {
    if (CONTEXT(ctx) != NULL) {
      dlsym_EVP_CIPHER_CTX_cleanup(context);
    } else {
      dlsym_EVP_CIPHER_CTX_free(context);
    }
  }
  if (jKey != NULL) {
    (*env)->ReleaseByteArrayElements(env, key, jKey, 0);
  }
  if (jIv != NULL) {
    (*env)->ReleaseByteArrayElements(env, iv, jIv, 0);
  }

  return result;
}

// https://www.openssl.org/docs/crypto/EVP_EncryptInit.html
static int check_update_max_output_len(EVP_CIPHER_CTX *context, int input_len,
    int max_output_len)
{
  if (context->flags & EVP_CIPH_NO_PADDING) {
    if (max_output_len >= input_len) {
      return 1;
    }
    return 0;
  } else {
    int b = context->cipher->block_size;
    if (context->encrypt) {
      if (max_output_len >= input_len + b - 1) {
        return 1;
      }
    } else {
      if (max_output_len >= input_len + b) {
        return 1;
      }
    }

    return 0;
  }
}

JNIEXPORT jint JNICALL Java_org_apache_commons_crypto_cipher_OpenSslNative_update
    (JNIEnv *env, jclass clazz, jlong ctx, jobject input, jint input_offset,
    jint input_len, jobject output, jint output_offset, jint max_output_len)
{
  EVP_CIPHER_CTX *context = CONTEXT(ctx);
  if (!check_update_max_output_len(context, input_len, max_output_len)) {
    THROW(env, "javax/crypto/ShortBufferException",  \
        "Output buffer is not sufficient.");
    return 0;
  }
  unsigned char *input_bytes = (*env)->GetDirectBufferAddress(env, input);
  unsigned char *output_bytes = (*env)->GetDirectBufferAddress(env, output);
  if (input_bytes == NULL || output_bytes == NULL) {
    THROW(env, "java/lang/InternalError", "Cannot get buffer address.");
    return 0;
  }
  input_bytes = input_bytes + input_offset;
  output_bytes = output_bytes + output_offset;

  int output_len = 0;
  if (!dlsym_EVP_CipherUpdate(context, output_bytes, &output_len,  \
      input_bytes, input_len)) {
    dlsym_EVP_CIPHER_CTX_cleanup(context);
    THROW(env, "java/lang/InternalError", "Error in EVP_CipherUpdate.");
    return 0;
  }
  return output_len;
}

JNIEXPORT jint JNICALL Java_org_apache_commons_crypto_cipher_OpenSslNative_updateByteArray
    (JNIEnv *env, jclass clazz, jlong ctx, jbyteArray input, jint input_offset,
    jint input_len, jbyteArray output, jint output_offset, jint max_output_len)
{
  EVP_CIPHER_CTX *context = CONTEXT(ctx);

  // when provide AAD to EVP cipher, output is NULL.
  if (output != NULL
        && !check_update_max_output_len(context, input_len, max_output_len)) {
    THROW(env, "javax/crypto/ShortBufferException",  \
        "Output buffer is not sufficient.");
    return 0;
  }

  unsigned char *input_bytes = NULL;
  unsigned char *output_bytes = NULL;
  int output_len = 0;

  input_bytes = (unsigned char *) (*env)->GetByteArrayElements(env, input, 0);

  // output is NULL when updateAAD
  if (output != NULL) {
    output_bytes = (unsigned char *) (*env)->GetByteArrayElements(env, output, 0);
  }
  if (input_bytes == NULL || (output != NULL && output_bytes == NULL)) {
    THROW(env, "java/lang/InternalError", "Cannot get buffer address.");
    return 0;
  }

  int rc = dlsym_EVP_CipherUpdate(context, output_bytes + output_offset, &output_len,  \
      input_bytes + input_offset, input_len);
  if (rc == 0) {
    dlsym_EVP_CIPHER_CTX_cleanup(context);
    THROW(env, "java/lang/InternalError", "Error in EVP_CipherUpdate.");
    output_len = 0;
  }

cleanup:
  if (input_bytes != NULL) {
    (*env)->ReleaseByteArrayElements(env, input, (jbyte *) input_bytes, 0);
  }
  if (output_bytes != NULL) {
    (*env)->ReleaseByteArrayElements(env, output, (jbyte *) output_bytes, 0);
  }

  return output_len;
}

JNIEXPORT jint JNICALL Java_org_apache_commons_crypto_cipher_OpenSslNative_updateByteArrayByteBuffer
    (JNIEnv *env, jclass clazz, jlong ctx, jbyteArray input, jint input_offset,
    jint input_len, jobject output, jint output_offset, jint max_output_len)
{
  EVP_CIPHER_CTX *context = CONTEXT(ctx);
  if (!check_update_max_output_len(context, input_len, max_output_len)) {
    THROW(env, "javax/crypto/ShortBufferException",  \
        "Output buffer is not sufficient.");
    return 0;
  }
  unsigned char *input_bytes = (unsigned char *) (*env)->GetByteArrayElements(env, input, 0);
  unsigned char *output_bytes = (*env)->GetDirectBufferAddress(env, output);
  if (input_bytes == NULL || output_bytes == NULL) {
    THROW(env, "java/lang/InternalError", "Cannot get buffer address.");
    return 0;
  }
  input_bytes = input_bytes + input_offset;
  output_bytes = output_bytes + output_offset;

  int output_len = 0;
  if (!dlsym_EVP_CipherUpdate(context, output_bytes, &output_len,  \
      input_bytes, input_len)) {
    (*env)->ReleaseByteArrayElements(env, input, (jbyte *) input_bytes, 0);
    dlsym_EVP_CIPHER_CTX_cleanup(context);
    THROW(env, "java/lang/InternalError", "Error in EVP_CipherUpdate.");
    return 0;
  }
  return output_len;
}


// https://www.openssl.org/docs/crypto/EVP_EncryptInit.html
static int check_doFinal_max_output_len(EVP_CIPHER_CTX *context,
    int max_output_len)
{
  if (context->flags & EVP_CIPH_NO_PADDING) {
    return 1;
  } else {
    int b = context->cipher->block_size;
    if (max_output_len >= b) {
      return 1;
    }

    return 0;
  }
}

JNIEXPORT jint JNICALL Java_org_apache_commons_crypto_cipher_OpenSslNative_doFinal
    (JNIEnv *env, jclass clazz, jlong ctx, jobject output, jint offset,
    jint max_output_len)
{
  EVP_CIPHER_CTX *context = CONTEXT(ctx);
  if (!check_doFinal_max_output_len(context, max_output_len)) {
    THROW(env, "javax/crypto/ShortBufferException",  \
        "Output buffer is not sufficient.");
    return 0;
  }
  unsigned char *output_bytes = (*env)->GetDirectBufferAddress(env, output);
  if (output_bytes == NULL) {
    THROW(env, "java/lang/InternalError", "Cannot get buffer address.");
    return 0;
  }
  output_bytes = output_bytes + offset;

  int output_len = 0;
  if (!dlsym_EVP_CipherFinal_ex(context, output_bytes, &output_len)) {
    // validate tag in GCM mode when decrypt
    if ((context->cipher->flags & EVP_CIPH_MODE) == EVP_CIPH_GCM_MODE
        && context->encrypt == DECRYPT_MODE) {
      THROW(env, "javax/crypto/AEADBadTagException", "Tag mismatch!");
    } else {
      THROW(env, "java/lang/InternalError", "Error in EVP_CipherFinal_ex.");
    }
    dlsym_EVP_CIPHER_CTX_cleanup(context);
    return 0;
  }
  return output_len;
}

JNIEXPORT jint JNICALL Java_org_apache_commons_crypto_cipher_OpenSslNative_doFinalByteArray
    (JNIEnv *env, jclass clazz, jlong ctx, jbyteArray output, jint offset,
     jint max_output_len)
{
  EVP_CIPHER_CTX *context = CONTEXT(ctx);
  if (!check_doFinal_max_output_len(context, max_output_len)) {
    THROW(env, "javax/crypto/ShortBufferException",  \
        "Output buffer is not sufficient.");
    return 0;
  }
  unsigned char *output_bytes = (unsigned char *) (*env)->GetByteArrayElements(env, output, 0);
  if (output_bytes == NULL) {
    THROW(env, "java/lang/InternalError", "Cannot get buffer address.");
    return 0;
  }

  int output_len = 0;
  int rc = dlsym_EVP_CipherFinal_ex(context, output_bytes + offset, &output_len);

  (*env)->ReleaseByteArrayElements(env, output, (jbyte *) output_bytes, 0);

  if (rc == 0) {
    // validate tag in GCM mode when decrypt
    if ((context->cipher->flags & EVP_CIPH_MODE) == EVP_CIPH_GCM_MODE
      && context->encrypt == DECRYPT_MODE) {
    THROW(env, "javax/crypto/AEADBadTagException", "Tag mismatch!");
    } else {
    THROW(env, "java/lang/InternalError", "Error in EVP_CipherFinal_ex.");
    }
    dlsym_EVP_CIPHER_CTX_cleanup(context);
    return 0;
  }
  return output_len;
}

JNIEXPORT jint JNICALL Java_org_apache_commons_crypto_cipher_OpenSslNative_ctrl
    (JNIEnv *env, jclass clazz, jlong ctx, jint type, jint arg, jbyteArray data)
{
  EVP_CIPHER_CTX *context = CONTEXT(ctx);

  int rc = 0;
  void *data_ptr = NULL;
  if (data != NULL) {
    data_ptr = (void*) (*env)->GetByteArrayElements(env, data, 0);
    if (data_ptr == NULL) {
      THROW(env, "java/lang/InternalError", "Cannot get buffer address.");
      return 0;
    }
  }

  // get/set tag for GCM
  if (type == EVP_CTRL_GCM_GET_TAG || type == EVP_CTRL_GCM_SET_TAG) {
    if (arg <= 0 || arg > 16) {
      THROW(env, "javax/crypto/AEADBadTagException", "TAG_LENGTH_INTERNAL_ERROR");
      goto exit_;
    }
    if (data == NULL) {
      THROW(env, "javax/crypto/AEADBadTagException", "tag is null");
      goto exit_;
    }

    unsigned char *tag = (unsigned char*) data_ptr;
    rc = dlsym_EVP_CIPHER_CTX_ctrl(context, type, arg, tag);
    if (!rc) {
      THROW(env, "javax/crypto/AEADBadTagException", "TAG_SET_ERROR or TAG_RETRIEVE_ERROR");
      goto exit_;
    }
  } else {
    THROW(env, "java.lang.UnsupportedOperationException", "Not implemented yet!");
    goto exit_;
  }

exit_:
  if (data_ptr != NULL) {
    (*env)->ReleaseByteArrayElements(env, data, (jbyte *) data_ptr, 0);
  }
  return rc;
}


JNIEXPORT void JNICALL Java_org_apache_commons_crypto_cipher_OpenSslNative_clean
    (JNIEnv *env, jclass clazz, jlong ctx)
{
  EVP_CIPHER_CTX *context = CONTEXT(ctx);
  if (context) {
    dlsym_EVP_CIPHER_CTX_free(context);
  }
}
