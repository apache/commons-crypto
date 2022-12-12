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
package org.apache.commons.crypto.random;

import java.security.GeneralSecurityException;
import java.util.Properties;
import java.util.Random;

import org.apache.commons.crypto.Crypto;

/**
 * <p>
 * OpenSSL secure random using JNI. This implementation is thread-safe.
 * </p>
 *
 * <p>
 * If using an Intel chipset with RDRAND, the high-performance hardware random number generator will be used and it's much faster than SecureRandom. If RDRAND
 * is unavailable, default OpenSSL secure random generator will be used. It's still faster and can generate strong random bytes.
 * </p>
 * <p>
 * This class is not public/protected so does not appear in the main Javadoc Please ensure that property use is documented in the enum
 * CryptoRandomFactory.RandomProvider
 * </p>
 *
 * @see <a href="https://wiki.openssl.org/index.php/Random_Numbers"> https://wiki.openssl.org/index.php/Random_Numbers</a>
 * @see <a href="http://en.wikipedia.org/wiki/RdRand"> http://en.wikipedia.org/wiki/RdRand</a>
 */
class OpenSslCryptoRandom implements CryptoRandom {

    private static final boolean nativeEnabled;

    private static final Throwable initException;

    static {
        boolean opensslLoaded = false;
        Throwable except = null;
        if (Crypto.isNativeCodeLoaded()) {
            try {
                OpenSslCryptoRandomNative.initSR();
                opensslLoaded = true;
            } catch (final Exception | UnsatisfiedLinkError e) {
                except = e;
            }
        }
        nativeEnabled = opensslLoaded;
        initException = except;
        //
        // Check that nextRandBytes works (is this really needed?)
        try {
            checkNative();
        } catch (final GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
        if (!OpenSslCryptoRandomNative.nextRandBytes(new byte[1])) {
            throw new IllegalStateException("Check of nextRandBytes failed");
        }
    }

    private static void checkNative() throws GeneralSecurityException {
        if (!nativeEnabled) {
            if (initException != null) {
                throw new GeneralSecurityException("Native library could not be initialized", initException);
            }
            throw new GeneralSecurityException("Native library is not loaded");
        }
    }

    /**
     * Judges whether native library was successfully loaded and initialized.
     *
     * @return true if library was loaded and initialized
     */
    public static boolean isNativeCodeEnabled() {
        return nativeEnabled;
    }

    /**
     * Constructs a {@link OpenSslCryptoRandom}.
     *
     * @param props the configuration properties - not used
     * @throws GeneralSecurityException if the native library could not be initialized successfully
     */
    public OpenSslCryptoRandom(final Properties props) throws GeneralSecurityException { // NOPMD
        checkNative();
    }

    /**
     * Overrides {@link java.lang.AutoCloseable#close()}.
     * Does nothing.
     */
    @Override
    public void close() {
        // noop
    }

    /**
     * Generates a user-specified number of random bytes. It's thread-safe.
     * Overrides {@link Random}.
     *
     * @param bytes the array to be filled in with random bytes.
     */
    @Override
    public void nextBytes(final byte[] bytes) {
        // Constructor ensures that native is enabled here
        if (!OpenSslCryptoRandomNative.nextRandBytes(bytes)) {
            // Assume it's a problem with the argument, rather than an internal issue
            throw new IllegalArgumentException("The nextRandBytes method failed");
        }
    }

}
