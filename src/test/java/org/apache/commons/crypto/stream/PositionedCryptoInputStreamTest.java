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

package org.apache.commons.crypto.stream;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Objects;
import java.util.Properties;
import java.util.Random;

import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.crypto.Crypto;
import org.apache.commons.crypto.cipher.AbstractCipherTest;
import org.apache.commons.crypto.cipher.CryptoCipher;
import org.apache.commons.crypto.stream.input.Input;
import org.apache.commons.crypto.utils.ReflectionUtils;
import org.junit.Assert;
import org.junit.Assume;
import org.junit.Before;
import org.junit.Test;

public class PositionedCryptoInputStreamTest {

    private final int dataLen = 20000;
    private final byte[] testData = new byte[dataLen];
    private byte[] encData;
    private final Properties props = new Properties();
    private final byte[] key = new byte[16];
    private final byte[] iv = new byte[16];
    private final int bufferSize = 2048;
    private final int bufferSizeLess = bufferSize - 1;
    private final int bufferSizeMore = bufferSize + 1;
    private final int length = 1024;
    private final int lengthLess = length - 1;
    private final int lengthMore = length + 1;

    private final String transformation = "AES/CTR/NoPadding";

    @Before
    public void before() throws IOException {
        final Random random = new SecureRandom();
        random.nextBytes(testData);
        random.nextBytes(key);
        random.nextBytes(iv);
        prepareData();
    }

    private void prepareData() throws IOException {
        CryptoCipher cipher = null;
        try {
            cipher = (CryptoCipher) ReflectionUtils.newInstance(
                    ReflectionUtils.getClassByName(AbstractCipherTest.JCE_CIPHER_CLASSNAME), props,
                    transformation);
        } catch (final ClassNotFoundException cnfe) {
            throw new IOException("Illegal crypto cipher!");
        }

        final ByteArrayOutputStream baos = new ByteArrayOutputStream();
        // encryption data
        final OutputStream out = new CryptoOutputStream(baos, cipher, bufferSize,
                new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
        out.write(testData);
        out.flush();
        out.close();
        encData = baos.toByteArray();
    }

    private PositionedCryptoInputStream getCryptoInputStream(
            final CryptoCipher cipher, final int bufferSize) throws IOException {
        return new PositionedCryptoInputStream(props, new PositionedInputForTest(
                Arrays.copyOf(encData, encData.length)), cipher, bufferSize,
                key, iv, 0);
    }
    
    private PositionedCryptoInputStream getCryptoInputStream(final int streamOffset) 
            throws IOException {
        return new PositionedCryptoInputStream(props, new PositionedInputForTest(
                Arrays.copyOf(encData, encData.length)), key, iv, streamOffset);
    }

    @Test
    public void doTestJCE() throws Exception {
        testCipher(AbstractCipherTest.JCE_CIPHER_CLASSNAME);
    }

    @Test
    public void doTestJNI() throws Exception {
        Assume.assumeTrue(Crypto.isNativeCodeLoaded());
        testCipher(AbstractCipherTest.OPENSSL_CIPHER_CLASSNAME);
    }

    protected void testCipher(final String cipherClass) throws Exception {
        doPositionedReadTests(cipherClass);
        doPositionedReadTests();
        doReadFullyTests(cipherClass);
        doReadFullyTests();
        doSeekTests(cipherClass);
        doSeekTests();
        doMultipleReadTest(cipherClass);
        doMultipleReadTest();
    }

    // when there are multiple positioned read actions and one read action,
    // they will not interfere each other.
    private void doMultipleReadTest(final String cipherClass) throws Exception {
        try (PositionedCryptoInputStream in = getCryptoInputStream(getCipher(cipherClass), bufferSize)) {
            int position = 0;
            while (in.available() > 0) {
                final ByteBuffer buf = ByteBuffer.allocate(length);
                final byte[] bytes1 = new byte[length];
                final byte[] bytes2 = new byte[lengthLess];
                // do the read and position read
                final int pn1 = in.read(position, bytes1, 0, length);
                final int n = in.read(buf);
                final int pn2 = in.read(position, bytes2, 0, lengthLess);

                // verify the result
                if (pn1 > 0) {
                    compareByteArray(testData, position, bytes1, pn1);
                }

                if (pn2 > 0) {
                    compareByteArray(testData, position, bytes2, pn2);
                }

                if (n > 0) {
                    compareByteArray(testData, position, buf.array(), n);
                    position += n;
                } else {
                    break;
                }
            }
        }
    }
    
    private void doMultipleReadTest() throws Exception{
        PositionedCryptoInputStream in = getCryptoInputStream(0);
        final String cipherClass = in.getCipher().getClass().getName();
        doMultipleReadTest(cipherClass);
    }

    private void doPositionedReadTests(final String cipherClass) throws Exception {
        // test with different bufferSize when position = 0
        testPositionedReadLoop(cipherClass, 0, length, bufferSize, dataLen);
        testPositionedReadLoop(cipherClass, 0, length, bufferSizeLess, dataLen);
        testPositionedReadLoop(cipherClass, 0, length, bufferSizeMore, dataLen);
        // test with different position when bufferSize = 2048
        testPositionedReadLoop(cipherClass, dataLen / 2, length, bufferSize,
                dataLen);
        testPositionedReadLoop(cipherClass, dataLen / 2 - 1, length,
                bufferSizeLess, dataLen);
        testPositionedReadLoop(cipherClass, dataLen / 2 + 1, length,
                bufferSizeMore, dataLen);
        // position = -1 or position = max length, read nothing and return -1
        testPositionedReadNone(cipherClass, -1, length, bufferSize);
        testPositionedReadNone(cipherClass, dataLen, length, bufferSize);
    }
    
    private void doPositionedReadTests() throws Exception {
    	PositionedCryptoInputStream in = getCryptoInputStream(0);
    	final String cipherClass = in.getCipher().getClass().getName();
    	doPositionedReadTests(cipherClass);
    }

    private void doReadFullyTests(final String cipherClass) throws Exception {
        // test with different bufferSize when position = 0
        testReadFullyLoop(cipherClass, 0, length, bufferSize, dataLen);
        testReadFullyLoop(cipherClass, 0, length, bufferSizeLess, dataLen);
        testReadFullyLoop(cipherClass, 0, length, bufferSizeMore, dataLen);
        // test with different length when position = 0
        testReadFullyLoop(cipherClass, 0, length, bufferSize, dataLen);
        testReadFullyLoop(cipherClass, 0, lengthLess, bufferSize, dataLen);
        testReadFullyLoop(cipherClass, 0, lengthMore, bufferSize, dataLen);
        // test read fully failed
        testReadFullyFailed(cipherClass, -1, length, bufferSize);
        testReadFullyFailed(cipherClass, dataLen, length, bufferSize);
        testReadFullyFailed(cipherClass, dataLen - length + 1, length,
                bufferSize);
    }
    
    private void doReadFullyTests() throws Exception {
        PositionedCryptoInputStream in = getCryptoInputStream(0);
        final String cipherClass = in.getCipher().getClass().getName();
        doReadFullyTests(cipherClass);
    }

    private void doSeekTests(final String cipherClass) throws Exception {
        // test with different length when position = 0
        testSeekLoop(cipherClass, 0, length, bufferSize);
        testSeekLoop(cipherClass, 0, lengthLess, bufferSize);
        testSeekLoop(cipherClass, 0, lengthMore, bufferSize);
        // there should be none data read when position = dataLen
        testSeekLoop(cipherClass, dataLen, length, bufferSize);
        // test exception when position = -1
        testSeekFailed(cipherClass, -1, bufferSize);
    }
    
    private void doSeekTests() throws Exception{
        PositionedCryptoInputStream in = getCryptoInputStream(0);
        final String cipherClass = in.getCipher().getClass().getName();
        doSeekTests(cipherClass);
    }

    private void testSeekLoop(final String cipherClass, int position, final int length,
            final int bufferSize) throws Exception {
        try (PositionedCryptoInputStream in = getCryptoInputStream(getCipher(cipherClass), bufferSize)) {
            while (in.available() > 0) {
                in.seek(position);
                final ByteBuffer buf = ByteBuffer.allocate(length);
                final int n = in.read(buf);
                if (n > 0) {
                    compareByteArray(testData, position, buf.array(), n);
                    position += n;
                } else {
                    break;
                }
            }
        }
    }

    // test for the out of index position, eg, -1.
    private void testSeekFailed(final String cipherClass, final int position, final int bufferSize)
            throws Exception {
        final PositionedCryptoInputStream in = getCryptoInputStream(
                getCipher(cipherClass), bufferSize);
        try {
            in.seek(position);
            Assert.fail("Excepted exception for cannot seek to negative offset.");
        } catch (final IllegalArgumentException iae) {
        }
        in.close();
    }

    private void testPositionedReadLoop(final String cipherClass, int position,
            final int length, final int bufferSize, final int total) throws Exception {
        try (PositionedCryptoInputStream in = getCryptoInputStream(getCipher(cipherClass), bufferSize)) {
            // do the position read until the end of data
            while (position < total) {
                final byte[] bytes = new byte[length];
                final int n = in.read(position, bytes, 0, length);
                if (n >= 0) {
                    compareByteArray(testData, position, bytes, n);
                    position += n;
                } else {
                    break;
                }
            }
        }
    }

    // test for the out of index position, eg, -1.
    private void testPositionedReadNone(final String cipherClass, final int position,
            final int length, final int bufferSize) throws Exception {
        try (PositionedCryptoInputStream in = getCryptoInputStream(getCipher(cipherClass), bufferSize)) {
            final byte[] bytes = new byte[length];
            final int n = in.read(position, bytes, 0, length);
            Assert.assertEquals(n, -1);
        }
    }

    private void testReadFullyLoop(final String cipherClass, int position,
            final int length, final int bufferSize, final int total) throws Exception {
        try (PositionedCryptoInputStream in = getCryptoInputStream(
                getCipher(cipherClass), bufferSize)) {

            // do the position read full until remain < length
            while (position + length <= total) {
                final byte[] bytes = new byte[length];
                in.readFully(position, bytes);
                compareByteArray(testData, position, bytes, length);
                position += length;
            }

        }
    }

    // test for the End of file reached before reading fully
    private void testReadFullyFailed(final String cipherClass, final int position,
            final int length, final int bufferSize) throws Exception {
        final PositionedCryptoInputStream in = getCryptoInputStream(
                getCipher(cipherClass), bufferSize);
        final byte[] bytes = new byte[length];
        try {
            in.readFully(position, bytes, 0, length);
            Assert.fail("Expected IOException.");
        } catch (final IOException ioe) {
            // excepted exception
        }
        in.close();
        in.close(); // Don't throw exception.
    }

    // compare the data from pos with length and data2 from 0 with length
    private void compareByteArray(final byte[] data1, final int pos, final byte[] data2,
            final int length) {
        final byte[] expectedData = new byte[length];
        final byte[] realData = new byte[length];
        // get the expected data with the position and length
        System.arraycopy(data1, pos, expectedData, 0, length);
        // get the real data
        System.arraycopy(data2, 0, realData, 0, length);
        Assert.assertArrayEquals(expectedData, realData);
    }

    private CryptoCipher getCipher(final String cipherClass) throws IOException {
        try {
            return (CryptoCipher) ReflectionUtils.newInstance(
                    ReflectionUtils.getClassByName(cipherClass), props,
                    transformation);
        } catch (final ClassNotFoundException cnfe) {
            throw new IOException("Illegal crypto cipher!");
        }
    }

    class PositionedInputForTest implements Input {

        byte[] data;
        long pos;
        long count;

        public PositionedInputForTest(final byte[] data) {
            this.data = data;
            this.pos = 0;
            this.count = data.length;
        }

        @Override
        public int read(final ByteBuffer dst) throws IOException {
            final int remaining = (int) (count - pos);
            if (remaining <= 0) {
                return -1;
            }

            final int length = Math.min(dst.remaining(), remaining);
            dst.put(data, (int) pos, length);
            pos += length;
            return length;
        }

        @Override
        public long skip(long n) throws IOException {
            if (n <= 0) {
                return 0;
            }

            final long remaining = count - pos;
            if (remaining < n) {
                n = remaining;
            }
            pos += n;

            return n;
        }

        @Override
        public int read(final long position, final byte[] buffer, final int offset, int length)
                throws IOException {
            Objects.requireNonNull(buffer, "buffer");
            if (offset < 0 || length < 0
                    || length > buffer.length - offset) {
                throw new IndexOutOfBoundsException();
            }

            if (position < 0 || position >= count) {
                return -1;
            }

            final long avail = count - position;
            if (length > avail) {
                length = (int) avail;
            }
            if (length <= 0) {
                return 0;
            }
            System.arraycopy(data, (int) position, buffer, offset, length);
            return length;
        }

        @Override
        public void seek(final long position) throws IOException {
            if (pos < 0) {
                throw new IOException("Negative seek offset");
            } else if (position >= 0 && position < count) {
                pos = position;
            } else {
                // to the end of file
                pos = count;
            }
        }

        @Override
        public void close() throws IOException {
        }

        @Override
        public int available() throws IOException {
            return (int) (count - pos);
        }
    }
}
