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

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.Properties;

import org.apache.commons.crypto.utils.IoUtils;

/**
 * A Random implementation that uses random bytes sourced from the operating system.
 * <p>
 * This class is not public/protected so does not appear in the main Javadoc Please ensure that property use is documented in the enum
 * CryptoRandomFactory.RandomProvider
 * </p>
 */
final class OsCryptoRandom implements CryptoRandom {

    private static final int RESERVOIR_LENGTH = 8192;

    private transient FileInputStream stream;

    private final byte[] reservoir = new byte[RESERVOIR_LENGTH];

    private int pos = reservoir.length;

    /**
     * Fills the reservoir.
     *
     * @param min the length.
     */
    private void fillReservoir(final int min) {
        if (pos >= reservoir.length - min) {
            try {
                IoUtils.readFully(stream, reservoir, 0, reservoir.length);
            } catch (final IOException e) {
                throw new IllegalStateException("failed to fill reservoir", e);
            }
            pos = 0;
        }
    }

    /**
     * Constructs a {@link OsCryptoRandom}.
     *
     * @param props the configuration properties.
     * Uses {@link CryptoRandomFactory#DEVICE_FILE_PATH_KEY} to determine the
     * path to the random device, default is
     * {@link CryptoRandomFactory#DEVICE_FILE_PATH_DEFAULT}
     */
    public OsCryptoRandom(final Properties props) {
        final File randomDevFile = new File(props.getProperty(CryptoRandomFactory.DEVICE_FILE_PATH_KEY, CryptoRandomFactory.DEVICE_FILE_PATH_DEFAULT));

        try {
            close();
            this.stream = new FileInputStream(randomDevFile);
        } catch (final IOException e) {
            throw new IllegalArgumentException(e);
        }

        try {
            fillReservoir(0);
        } catch (final IllegalStateException e) {
            close();
            throw e;
        }
    }

    /**
     * Overrides {@link CryptoRandom#nextBytes(byte[])}. Generates random bytes
     * and places them into a user-supplied byte array. The number of random
     * bytes produced is equal to the length of the byte array.
     *
     * @param bytes the array to be filled in with random bytes.
     */
    @Override
    synchronized public void nextBytes(final byte[] bytes) {
        int off = 0;
        int n = 0;
        while (off < bytes.length) {
            fillReservoir(0);
            n = Math.min(bytes.length - off, reservoir.length - pos);
            System.arraycopy(reservoir, pos, bytes, off, n);
            off += n;
            pos += n;
        }
    }

    /**
     * Overrides {@link java.lang.AutoCloseable#close()}. Closes the OS stream.
     */
    @Override
    synchronized public void close() {
        if (stream != null) {
            IoUtils.closeQuietly(stream);
            stream = null;
        }
    }

}
