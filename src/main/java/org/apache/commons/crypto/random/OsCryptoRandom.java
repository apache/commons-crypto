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

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.Properties;
import java.util.Random;

import org.apache.commons.crypto.conf.ConfigurationKeys;
import org.apache.commons.crypto.utils.IOUtils;
import org.apache.commons.crypto.utils.Utils;

/**
 * A Random implementation that uses random bytes sourced from the operating
 * system.
 */
class OsCryptoRandom extends Random implements CryptoRandom {

    private static final long serialVersionUID = 6391500337172057900L;

    private static final int RESERVOIR_LENGTH = 8192;

    private transient FileInputStream stream;

    private final byte[] reservoir = new byte[RESERVOIR_LENGTH];

    private int pos = reservoir.length;

    /**
     * Fills the reservoir.
     *
     * @param min the length.
     */
    private void fillReservoir(int min) {
        if (pos >= reservoir.length - min) {
            try {
                IOUtils.readFully(stream, reservoir, 0, reservoir.length);
            } catch (IOException e) {
                throw new RuntimeException("failed to fill reservoir", e);
            }
            pos = 0;
        }
    }

    /**
     * Constructs a {@link OsCryptoRandom}.
     *
     * @param props the configuration properties.
     * Uses {@link ConfigurationKeys#SECURE_RANDOM_DEVICE_FILE_PATH_KEY} to determine the
     * path to the random device, default is
     * {@link ConfigurationKeys#SECURE_RANDOM_DEVICE_FILE_PATH_DEFAULT}
     */
    public OsCryptoRandom(Properties props) {
        File randomDevFile = new File(getRandomDevPath(props));

        try {
            close();
            this.stream = new FileInputStream(randomDevFile);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        try {
            fillReservoir(0);
        } catch (RuntimeException e) {
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
    synchronized public void nextBytes(byte[] bytes) {
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
     * Overrides Random#next(). Generates the next pseudorandom number.
     * Subclasses should override this, as this is used by all other methods.
     *
     * @param nbits random bits.
     * @return the next pseudorandom value from this random number generator's
     *         sequence.
     */
    @Override
    synchronized protected int next(int nbits) {
        fillReservoir(4);
        int n = 0;
        for (int i = 0; i < 4; i++) {
            n = (n << 8) | (reservoir[pos++] & 0xff);
        }
        return n & (0xffffffff >> (32 - nbits));
    }

    /**
     * Overrides {@link java.lang.AutoCloseable#close()}. Closes the OS stream.
     */
    @Override
    synchronized public void close() {
        if (stream != null) {
            IOUtils.cleanup(stream);
            stream = null;
        }
    }

    /**
     * Gets the random device path.
     *
     * @param props The <code>Properties</code> class represents a set of
     *        properties.
     * @return the random device path based on the props.
     */
    private static String getRandomDevPath(Properties props) {
        String devPath = Utils.getProperties(props)
            .getProperty(ConfigurationKeys.SECURE_RANDOM_DEVICE_FILE_PATH_KEY);
        if (devPath == null) {
            devPath = System.getProperty(
                ConfigurationKeys.SECURE_RANDOM_DEVICE_FILE_PATH_KEY,
                ConfigurationKeys.SECURE_RANDOM_DEVICE_FILE_PATH_DEFAULT);
        }
        return devPath;
    }

}
