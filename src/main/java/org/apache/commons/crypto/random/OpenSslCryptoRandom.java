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
package org.apache.commons.crypto.random;

import java.security.GeneralSecurityException;
import java.util.Properties;
import java.util.Random;

import org.apache.commons.crypto.Crypto;
import org.apache.commons.crypto.utils.Utils;

/**
 * <p>
 * OpenSSL secure random using JNI. This implementation is thread-safe.
 * </p>
 *
 * <p>
 * If using an Intel chipset with RDRAND, the high-performance hardware random
 * number generator will be used and it's much faster than SecureRandom. If
 * RDRAND is unavailable, default OpenSSL secure random generator will be used.
 * It's still faster and can generate strong random bytes.
 * </p>
 *
 * @see <a href="https://wiki.openssl.org/index.php/Random_Numbers">
 *      https://wiki.openssl.org/index.php/Random_Numbers</a>
 * @see <a href="http://en.wikipedia.org/wiki/RdRand">
 *      http://en.wikipedia.org/wiki/RdRand</a>
 */
class OpenSslCryptoRandom extends Random implements CryptoRandom {
    private static final long serialVersionUID = -7828193502768789584L;

    private static final boolean nativeEnabled;

    private static final Throwable initException;

    static {
        boolean opensslLoaded = false;
        Throwable except = null;
        if (Crypto.isNativeCodeLoaded()) {
            try {
                OpenSslCryptoRandomNative.initSR();
                opensslLoaded = true;
            } catch (final Exception t) {
                except = t;
            } catch (final UnsatisfiedLinkError t) {
                except = t;
            }
        }
        nativeEnabled = opensslLoaded;
        initException = except;
    }

    /**
     * Judges whether native library was successfully loaded and initialised.
     *
     * @return true if library was loaded and initialised
     */
    public static boolean isNativeCodeEnabled() {
        return nativeEnabled;
    }

    /**
     * Constructs a {@link OpenSslCryptoRandom}.
     *
     * @param props the configuration properties - not used
     * @throws GeneralSecurityException if the native library could not be initialised successfully
     */
    // N.B. this class is not public/protected so does not appear in the main Javadoc
    // Please ensure that property use is documented in the enum CryptoRandomFactory.RandomProvider
    public OpenSslCryptoRandom(final Properties props) throws GeneralSecurityException { // NOPMD
        if (!nativeEnabled) {
            if (initException != null) {
                throw new GeneralSecurityException("Native library could not be initialised", initException);
            }
            throw new GeneralSecurityException("Native library is not loaded");
        }
        // Check that nextRandBytes works (is this really needed?)
        if (!OpenSslCryptoRandomNative.nextRandBytes(new byte[1])) {
            throw new GeneralSecurityException("Check of nextRandBytes failed");
        }
    }

    /**
     * Generates a user-specified number of random bytes. It's thread-safe.
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

    /**
     * Overrides {@link OpenSslCryptoRandom}. For {@link OpenSslCryptoRandom},
     * we don't need to set seed.
     *
     * @param seed the initial seed.
     */
    @Override
    public void setSeed(final long seed) {
        // Self-seeding.
    }

    /**
     * Overrides Random#next(). Generates an integer containing the
     * user-specified number of random bits(right justified, with leading
     * zeros).
     *
     * @param numBits number of random bits to be generated, where 0
     *        {@literal <=} {@code numBits} {@literal <=} 32.
     * @return int an {@code int} containing the user-specified number of
     *         random bits (right justified, with leading zeros).
     */
    @Override
    final protected int next(final int numBits) {
        Utils.checkArgument(numBits >= 0 && numBits <= 32);
        final int numBytes = (numBits + 7) / 8;
        final byte b[] = new byte[numBytes];
        int next = 0;

        nextBytes(b);
        for (int i = 0; i < numBytes; i++) {
            next = (next << 8) + (b[i] & 0xFF);
        }

        return next >>> (numBytes * 8 - numBits);
    }

    /**
     * Overrides {@link java.lang.AutoCloseable#close()}.
     * Does nothing.
     */
    @Override
    public void close() {
    }
}
