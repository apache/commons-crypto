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

import java.lang.Thread.State;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.junit.Test;

public abstract class AbstractRandomTest {

    public abstract CryptoRandom getCryptoRandom()
            throws GeneralSecurityException;

    @Test(timeout = 120000)
    public void testRandomBytes() throws Exception {
        try (CryptoRandom random = getCryptoRandom()) {
            // len = 16
            checkRandomBytes(random, 16);
            // len = 32
            checkRandomBytes(random, 32);
            // len = 128
            checkRandomBytes(random, 128);
            // len = 256
            checkRandomBytes(random, 256);
        }
    }

    @Test(timeout = 120000)
    public void testRandomBytesMultiThreaded() throws Exception {
        final int threadCount = 100;
        try (final CryptoRandom random = getCryptoRandom()) {
            final List<Thread> threads = new ArrayList<>(threadCount);

            for (int i = 0; i < threadCount; i++) {
                final Thread t = new Thread(() -> {
                    checkRandomBytes(random, 10);
                    checkRandomBytes(random, 1000);
                    checkRandomBytes(random, 100000);
                });
                t.start();
                threads.add(t);
            }

            for (final Thread t : threads) {
                if (!t.getState().equals(State.NEW)) {
                    t.join();
                }
            }

        }
    }

    /**
     * Test will timeout if secure random implementation always returns a
     * constant value.
     */
    private void checkRandomBytes(final CryptoRandom random, final int len) {
        final byte[] bytes = new byte[len];
        final byte[] bytes1 = new byte[len];
        random.nextBytes(bytes);
        random.nextBytes(bytes1);

        while (Arrays.equals(bytes1, new byte[len]) || Arrays.equals(bytes, bytes1)) {
            random.nextBytes(bytes1);
        }
    }
}
