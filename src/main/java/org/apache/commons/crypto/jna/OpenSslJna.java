/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */
package org.apache.commons.crypto.jna;

import org.apache.commons.crypto.cipher.CryptoCipher;
import org.apache.commons.crypto.random.CryptoRandom;

/**
 * Public class to give access to the package protected class objects
 */
public final class OpenSslJna {

    /**
     * @return The cipher class of JNA implementation
     */
    public static Class<? extends CryptoCipher> getCipherClass() {
        return OpenSslJnaCipher.class;
    }

    /**
     * @return The random class of JNA implementation
     */
    public static Class<? extends CryptoRandom> getRandomClass() {
        return OpenSslJnaCryptoRandom.class;
    }

    /**
     * @return true if JNA native loads successfully
     */
    public static boolean isEnabled() {
        return OpenSslNativeJna.INIT_OK;
    }

    /**
     * @return the error of JNA
     */
    public static Throwable initialisationError() {
        return OpenSslNativeJna.INIT_ERROR;
    }

    /**
     * Retrieves version/build information about OpenSSL library.
     *
     * @param type type can be OPENSSL_VERSION, OPENSSL_CFLAGS, OPENSSL_BUILT_ON...
     * @return A pointer to a constant string describing the version of the
     * OpenSSL library or giving information about the library build.
     */
    static String OpenSSLVersion(final int type) {
         return OpenSslNativeJna.OpenSSLVersion(type);
    }
}
