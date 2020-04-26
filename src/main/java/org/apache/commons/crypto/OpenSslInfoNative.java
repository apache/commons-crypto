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
package org.apache.commons.crypto;

import org.apache.commons.crypto.random.CryptoRandom;

/**
 * JNI interface of {@link CryptoRandom} implementation for OpenSSL.
 * The native method in this class is defined in
 * OpenSslCryptoRandomNative.h (generated at build time by javah)
 * and implemented in the file
 * src/main/native/org/apache/commons/crypto/random/OpenSslCryptoRandomNative.c
 */
class OpenSslInfoNative {

    public static final long VERSION_1_0_2X = 0x10002000;
    public static final long VERSION_1_1_0X = 0x10100000;

    /**
     * Makes the constructor private.
     */
    private OpenSslInfoNative() {
    }

    /**
     * @return version of native
     */
    public static native String NativeVersion();

    /**
     * @return name of native
     */
    public static native String NativeName();

    /**
     * @return timestamp of native
     */
    public static native String NativeTimeStamp();


    /**
     * @return the value of OPENSSL_VERSION_NUMBER.
     */
    public static native long OpenSSL();

    /**
     * Returns OpenSSL_version according the version type.
     *
     * @param type The version type
     * @return The text variant of the version number and the release date.
     */
    public static native String OpenSSLVersion(int type);
}
