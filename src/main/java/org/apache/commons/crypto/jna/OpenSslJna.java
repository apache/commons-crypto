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
 */
package org.apache.commons.crypto.jna;

import java.util.Objects;

import org.apache.commons.crypto.Crypto;
import org.apache.commons.crypto.cipher.CryptoCipher;
import org.apache.commons.crypto.random.CryptoRandom;
import org.apache.commons.crypto.utils.Utils;

/**
 * Provides access to package protected class objects and a {@link #main(String[])} method that prints version information.
 */
public final class OpenSslJna {

    /**
     * Logs debug messages.
     *
     * @param format See {@link String#format(String, Object...)}.
     * @param args   See {@link String#format(String, Object...)}.
     */
    static void debug(final Object format, final Object... args) {
        if (Crypto.IS_DEBUG) {
            System.out.println(String.format(Objects.toString(format), args));
        }
    }

    /**
     * Gets the cipher class of JNA implementation.
     *
     * @return The cipher class of JNA implementation.
     */
    public static Class<? extends CryptoCipher> getCipherClass() {
        return OpenSslJnaCipher.class;
    }

    /**
     * Gets the random class of JNA implementation.
     *
     * @return The random class of JNA implementation.
     */
    public static Class<? extends CryptoRandom> getRandomClass() {
        return OpenSslJnaCryptoRandom.class;
    }

    /**
     * Logs info-level messages.
     *
     * @param format See {@link String#format(String, Object...)}.
     * @param args   See {@link String#format(String, Object...)}.
     */
    private static void info(final String format, final Object... args) {
        // TODO Find a better way to do this later.
        System.out.println(String.format(format, args));
    }

    /**
     * Gets the error from the JNA.
     *
     * @return the error from the JNA.
     */
    public static Throwable initialisationError() {
        return OpenSslNativeJna.INIT_ERROR;
    }

    /**
     * Tests whether NA native loads successfully.
     *
     * @return {@code true} if JNA native loaded successfully.
     */
    public static boolean isEnabled() {
        return OpenSslNativeJna.INIT_OK;
    }

    /**
     * Main API.
     *
     * @param args command line arguments.
     * @throws Throwable Throws value from {@link #initialisationError()}.
     */
    public static void main(final String[] args) throws Throwable {
        // These are used by JNA code if defined:
        info("%s=%s", Crypto.JNA_LIBRARY_PATH_PROPERTY, System.getProperty(Crypto.JNA_LIBRARY_PATH_PROPERTY));
        info("jna.platform.library.path=%s", System.getProperty("jna.platform.library.path"));
        info("%s=%s\n", Crypto.JNA_LIBRARY_NAME_PROPERTY, System.getProperty(Crypto.JNA_LIBRARY_NAME_PROPERTY));
        // can set jna.debug_load=true for loading info
        info(Crypto.getComponentName() + " OpenSslJna: enabled = %s, version = 0x%08X", isEnabled(), OpenSslNativeJna.VERSION);
        final Throwable initialisationError = initialisationError();
        if (initialisationError != null) {
            info("initialisationError(): %s", initialisationError);
            System.err.flush(); // helpful for stack traces to not mix in other output.
            throw initialisationError; // propagate to make error obvious
        }
        info("OpenSSL library loaded OK, version: 0x%s", Long.toHexString(OpenSslNativeJna.OpenSSL_version_num()));
        for (int i = 0; i <= Utils.OPENSSL_VERSION_MAX_INDEX; i++) {
            final String data = OpenSslNativeJna.OpenSSLVersion(i);
            if (!"not available".equals(data)) {
                info("OpenSSLVersion(%d): %s", i, data);
            }
        }
    }

    /**
     * Constructs a new instance.
     *
     * @deprecated Will be private in the next major release.
     */
    @Deprecated
    public OpenSslJna() {
        // empty
    }
}
