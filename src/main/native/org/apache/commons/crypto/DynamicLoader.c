/*
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

/*
Shared code to load and unload the library.
*/

#include "org_apache_commons_crypto.h"

static HMODULE openssl; // the cached pointer
HMODULE open_library(JNIEnv *env)

{
  if (!openssl) {
    const char *libraryPath = COMMONS_CRYPTO_OPENSSL_LIBRARY;
    jclass clazz = (*env)->FindClass(env, "org/apache/commons/crypto/utils/Utils");
    if (clazz) {
        jmethodID libraryPathFunc = (*env)->GetStaticMethodID(env, clazz, "libraryPath", "(Ljava/lang/String;)Ljava/lang/String;");
        if (libraryPathFunc) {
            jstring defaultLibrary = (*env)->NewStringUTF(env, COMMONS_CRYPTO_OPENSSL_LIBRARY);
            jstring result = (jstring) (*env)->CallStaticObjectMethod(env, clazz, libraryPathFunc, defaultLibrary);
            if (result) {
                libraryPath = (*env)->GetStringUTFChars(env, result, NULL);
            }
        }
    }
#ifdef UNIX
    openssl = dlopen(libraryPath, RTLD_LAZY | RTLD_GLOBAL);
#endif

#ifdef WINDOWS
    openssl = LoadLibrary(libraryPath);
#endif

  }
  return openssl;
}

void close_library() {
    openssl = NULL;
}
