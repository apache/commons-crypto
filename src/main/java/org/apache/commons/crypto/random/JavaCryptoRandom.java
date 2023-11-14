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

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Properties;

import org.apache.commons.crypto.utils.Utils;

/**
 * A CryptoRandom of Java implementation.
 * <p>
 * This class is not public/protected so does not appear in the main Javadoc Please ensure that property use is documented in the enum
 * CryptoRandomFactory.RandomProvider
 * </p>
 */
final class JavaCryptoRandom implements CryptoRandom {

    private final SecureRandom instance;

    /**
     * Constructs a {@link JavaCryptoRandom}.
     *
     * @param properties the configuration properties. Uses the key {@link CryptoRandomFactory#JAVA_ALGORITHM_KEY} to get the name of the algorithm, with a
     *        default of {@link CryptoRandomFactory#JAVA_ALGORITHM_DEFAULT}
     */
    public JavaCryptoRandom(final Properties properties) {
        SecureRandom tmp;
        try {
            tmp = SecureRandom.getInstance(properties.getProperty(CryptoRandomFactory.JAVA_ALGORITHM_KEY, CryptoRandomFactory.JAVA_ALGORITHM_DEFAULT));
        } catch (final NoSuchAlgorithmException e) {
            tmp = new SecureRandom();
        }
        instance = tmp;
    }

    /**
     * Overrides {@link java.lang.AutoCloseable#close()}. For {@link JavaCryptoRandom}, we don't need to recycle resource.
     */
    @Override
    public void close() {
        // do nothing
    }

    /**
     * Overrides Random#next(). Generates an integer containing the user-specified number of random bits(right justified, with leading zeros).
     *
     * @param numBits number of random bits to be generated, where 0 {@literal <=} {@code numBits} {@literal <=} 32.
     * @return int an {@code int} containing the user-specified number of random bits (right justified, with leading zeros).
     */
    protected int next(final int numBits) {
        Utils.checkArgument(numBits >= 0 && numBits <= Integer.SIZE);
        // Can't simply invoke instance.next(bits) here, because that is package protected.
        // But, this should do.
        return instance.nextInt() >>> (Integer.SIZE - numBits);
    }

    /**
     * Overrides {@link CryptoRandom#nextBytes(byte[])}. Generates random bytes and places them into a user-supplied byte array. The number of random bytes
     * produced is equal to the length of the byte array.
     *
     * @param bytes the array to be filled in with random bytes.
     */
    @Override
    public void nextBytes(final byte[] bytes) {
        instance.nextBytes(bytes);
    }
}
