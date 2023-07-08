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
package org.apache.commons.crypto.stream;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
import static org.junit.jupiter.api.Assumptions.assumeFalse;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.channels.Channels;
import java.nio.channels.ReadableByteChannel;
import java.security.Key;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Properties;
import java.util.Random;
import java.util.concurrent.TimeUnit;

import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;

import org.apache.commons.crypto.Crypto;
import org.apache.commons.crypto.cipher.AbstractCipherTest;
import org.apache.commons.crypto.cipher.CryptoCipher;
import org.apache.commons.crypto.utils.AES;
import org.apache.commons.crypto.utils.ReflectionUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

public abstract class AbstractCipherStreamTest {

    protected static int defaultBufferSize = 8192;
    protected static int smallBufferSize = 1024;
    protected final int dataLen = 20000;
    protected final byte[] data = new byte[dataLen];
    protected byte[] encData;
    private final Properties props = new Properties();
    protected byte[] key = new byte[16];
    protected byte[] iv = new byte[16];
    protected int count = 10000;

    protected String transformation;

    public void assumeJniPresence(final String cipherClass) {
        assumeFalse(AbstractCipherTest.OPENSSL_CIPHER_CLASSNAME.equals(cipherClass) && !Crypto.isNativeCodeLoaded());
    }

    @BeforeEach
    public void before() throws Exception {
        final Random random = new SecureRandom();
        random.nextBytes(data);
        random.nextBytes(key);
        random.nextBytes(iv);
        setUp();
        prepareData();
    }

    private void byteBufferFinalReadCheck(final InputStream in, final ByteBuffer buf, final int bufPos)
            throws Exception {
        buf.position(bufPos);
        int len = 0;
        int n = 0;
        do {
            n = ((ReadableByteChannel) in).read(buf);
            len += n;
        } while (n > 0);
        buf.rewind();
        final byte[] readData = new byte[len + 1];
        buf.get(readData);
        final byte[] expectedData = new byte[len + 1];
        System.arraycopy(data, 0, expectedData, 0, len + 1);
        assertArrayEquals(readData, expectedData);
    }

    private void byteBufferReadCheck(final InputStream in, final ByteBuffer buf, final int bufPos)
            throws Exception {
        buf.position(bufPos);
        final int n = ((ReadableByteChannel) in).read(buf);
        assertEquals(bufPos + n, buf.position());
        final byte[] readData = new byte[n];
        buf.rewind();
        buf.position(bufPos);
        buf.get(readData);
        final byte[] expectedData = new byte[n];
        System.arraycopy(data, 0, expectedData, 0, n);
        assertArrayEquals(readData, expectedData);

        assertThrows(IndexOutOfBoundsException.class, () -> in.read(readData, -1, 0));
    }

    protected void doByteBufferRead(final String cipherClass, final boolean withChannel)
        throws Exception {
        // Skip this test if no JNI
        assumeJniPresence(cipherClass);
        ByteBuffer buf = ByteBuffer.allocate(dataLen + 100);
        // Default buffer size, initial buffer position is 0
        try (InputStream in = newCryptoInputStream(new ByteArrayInputStream(encData), getCipher(cipherClass),
            defaultBufferSize, iv, withChannel)) {
            byteBufferReadCheck(in, buf, 0);
        }

        // Default buffer size, initial buffer position is not 0
        try (InputStream in = newCryptoInputStream(new ByteArrayInputStream(encData), getCipher(cipherClass),
            defaultBufferSize, iv, withChannel)) {
            buf.clear();
            byteBufferReadCheck(in, buf, 11);
        }

        // Small buffer size, initial buffer position is 0
        try (InputStream in = newCryptoInputStream(new ByteArrayInputStream(encData), getCipher(cipherClass),
            smallBufferSize, iv, withChannel)) {
            buf.clear();
            byteBufferReadCheck(in, buf, 0);
        }

        // Small buffer size, initial buffer position is not 0
        try (InputStream in = newCryptoInputStream(new ByteArrayInputStream(encData), getCipher(cipherClass),
            smallBufferSize, iv, withChannel)) {
            buf.clear();
            byteBufferReadCheck(in, buf, 11);
        }

        // Direct buffer, default buffer size, initial buffer position is 0
        try (InputStream in = newCryptoInputStream(new ByteArrayInputStream(encData), getCipher(cipherClass),
            defaultBufferSize, iv, withChannel)) {
            buf = ByteBuffer.allocateDirect(dataLen + 100);
            byteBufferReadCheck(in, buf, 0);
        }

        // Direct buffer, default buffer size, initial buffer position is not 0
        try (InputStream in = newCryptoInputStream(new ByteArrayInputStream(encData), getCipher(cipherClass),
            defaultBufferSize, iv, withChannel)) {
            buf.clear();
            byteBufferReadCheck(in, buf, 11);
        }

        // Direct buffer, small buffer size, initial buffer position is 0
        try (InputStream in = newCryptoInputStream(new ByteArrayInputStream(encData), getCipher(cipherClass),
            smallBufferSize, iv, withChannel)) {
            buf.clear();
            byteBufferReadCheck(in, buf, 0);
        }

        // Direct buffer, small buffer size, initial buffer position is not 0
        try (InputStream in = newCryptoInputStream(new ByteArrayInputStream(encData), getCipher(cipherClass),
            smallBufferSize, iv, withChannel)) {
            buf.clear();
            byteBufferReadCheck(in, buf, 11);
        }

        // Direct buffer, small buffer size, initial buffer position is 0, final read
        try (InputStream in = newCryptoInputStream(new ByteArrayInputStream(encData), getCipher(cipherClass),
            smallBufferSize, iv, withChannel)) {
            buf.clear();
            byteBufferFinalReadCheck(in, buf, 0);
        }

        // Default buffer size, initial buffer position is 0, insufficient dest buffer length
        try (InputStream in = newCryptoInputStream(new ByteArrayInputStream(encData), getCipher(cipherClass),
            defaultBufferSize, iv, withChannel)) {
            buf = ByteBuffer.allocate(100);
            byteBufferReadCheck(in, buf, 0);
        }

        // Default buffer size, initial buffer position is 0
        try (InputStream in = newCryptoInputStream(transformation, props, new ByteArrayInputStream(encData), key,
            new IvParameterSpec(iv), withChannel)) {
            buf = ByteBuffer.allocate(dataLen + 100);
            byteBufferReadCheck(in, buf, 0);
        }

        // Default buffer size, initial buffer position is not 0
        try (InputStream in = newCryptoInputStream(transformation, props, new ByteArrayInputStream(encData), key,
            new IvParameterSpec(iv), withChannel)) {
            buf.clear();
            byteBufferReadCheck(in, buf, 11);
        }

        // Small buffer size, initial buffer position is 0
        try (InputStream in = newCryptoInputStream(transformation, props, new ByteArrayInputStream(encData), key,
            new IvParameterSpec(iv), withChannel)) {
            buf.clear();
            byteBufferReadCheck(in, buf, 0);
        }

        // Small buffer size, initial buffer position is not 0
        try (InputStream in = newCryptoInputStream(transformation, props, new ByteArrayInputStream(encData), key,
            new IvParameterSpec(iv), withChannel)) {
            buf.clear();
            byteBufferReadCheck(in, buf, 11);
        }

        // Direct buffer, default buffer size, initial buffer position is 0
        try (InputStream in = newCryptoInputStream(transformation, props, new ByteArrayInputStream(encData), key,
            new IvParameterSpec(iv), withChannel)) {
            buf = ByteBuffer.allocateDirect(dataLen + 100);
            byteBufferReadCheck(in, buf, 0);
        }

        // Direct buffer, default buffer size, initial buffer position is not 0
        try (InputStream in = newCryptoInputStream(transformation, props, new ByteArrayInputStream(encData), key,
            new IvParameterSpec(iv), withChannel)) {
            buf.clear();
            byteBufferReadCheck(in, buf, 11);
        }

        // Direct buffer, small buffer size, initial buffer position is 0
        try (InputStream in = newCryptoInputStream(transformation, props, new ByteArrayInputStream(encData), key,
            new IvParameterSpec(iv), withChannel)) {
            buf.clear();
            byteBufferReadCheck(in, buf, 0);
        }

        // Direct buffer, small buffer size, initial buffer position is not 0
        try (InputStream in = newCryptoInputStream(transformation, props, new ByteArrayInputStream(encData), key,
            new IvParameterSpec(iv), withChannel)) {
            buf.clear();
            byteBufferReadCheck(in, buf, 11);
        }

        // Direct buffer, default buffer size, initial buffer position is 0, final read
        try (InputStream in = newCryptoInputStream(transformation, props, new ByteArrayInputStream(encData), key,
            new IvParameterSpec(iv), withChannel)) {
            buf.clear();
            byteBufferFinalReadCheck(in, buf, 0);
        }

        // Default buffer size, initial buffer position is 0, insufficient dest buffer length
        try (InputStream in = newCryptoInputStream(transformation, props, new ByteArrayInputStream(encData), key,
            new IvParameterSpec(iv), withChannel)) {
            buf = ByteBuffer.allocate(100);
            byteBufferReadCheck(in, buf, 0);
        }
    }

    private void doByteBufferWrite(final CryptoOutputStream out, final boolean withChannel) throws Exception {
        ByteBuffer buf = ByteBuffer.allocateDirect(dataLen / 2);
        buf.put(data, 0, dataLen / 2);
        buf.flip();
        final int n1 = out.write(buf);

        buf.clear();
        buf.put(data, n1, dataLen / 3);
        buf.flip();
        final int n2 = out.write(buf);

        buf.clear();
        buf.put(data, n1 + n2, dataLen - n1 - n2 - 1);
        buf.flip();
        final int n3 = out.write(buf);

        out.write(1);

        assertEquals(dataLen, n1 + n2 + n3 + 1);

        assertThrows(IndexOutOfBoundsException.class, () -> out.write(data, 0, data.length + 1));
        out.flush();

        try (InputStream in = newCryptoInputStream(
                new ByteArrayInputStream(encData), out.getCipher(),
                defaultBufferSize, iv, withChannel)) {
            buf = ByteBuffer.allocate(dataLen + 100);
            byteBufferReadCheck(in, buf, 0);
        }
    }

    protected void doByteBufferWrite(final String cipherClass,
            final ByteArrayOutputStream baos, final boolean withChannel)
            throws Exception {
        assumeJniPresence(cipherClass);
        baos.reset();
        CryptoOutputStream out = newCryptoOutputStream(baos, getCipher(cipherClass), defaultBufferSize, iv, withChannel);
        doByteBufferWrite(out, withChannel);

        baos.reset();
        try (final CryptoCipher cipher = getCipher(cipherClass)) {
            final String transformation = cipher.getAlgorithm();
            out = newCryptoOutputStream(transformation, props, baos, key, new IvParameterSpec(iv), withChannel);
            doByteBufferWrite(out, withChannel);
            out.write(1);
            assertTrue(out.isOpen());

            out = newCryptoOutputStream(transformation, props, baos, key, new IvParameterSpec(iv), withChannel);
            out.close();
            assertFalse(out.isOpen());
        }
    }

    protected void doExceptionTest(final String cipherClass, final ByteArrayOutputStream baos,
            final boolean withChannel) throws IOException {
        assumeJniPresence(cipherClass);

        // Test InvalidAlgorithmParameters
       Exception ex = assertThrows(IOException.class, () -> newCryptoInputStream(transformation, props, new ByteArrayInputStream(encData),
               AES.newSecretKeySpec(key), new GCMParameterSpec(0, new byte[0]), withChannel));
        assertEquals(ex.getMessage(),"Illegal parameters");
        // Test InvalidAlgorithmParameters
        ex =  assertThrows(IOException.class, () -> newCryptoOutputStream(transformation, props, baos,
                AES.newSecretKeySpec(key), new GCMParameterSpec(0,
                        new byte[0]), withChannel));
        assertEquals(ex.getMessage(),"Illegal parameters");

        // Test Invalid Key
        assertThrows(IOException.class, () -> newCryptoInputStream(transformation, props, new ByteArrayInputStream(encData),
                AES.newSecretKeySpec(new byte[10]), new IvParameterSpec(iv), withChannel));
        // Test Invalid Key
        assertThrows(IOException.class, () -> newCryptoOutputStream(transformation, props, baos, new byte[10],
                new IvParameterSpec(iv), withChannel));

        // Test reading a closed stream.
        InputStream closedIn;
        try (final InputStream in = newCryptoInputStream(new ByteArrayInputStream(encData),
                getCipher(cipherClass), defaultBufferSize, iv, withChannel)) {
            closedIn = in;
        }
        // Throw exception.
        ex = assertThrows(IOException.class, closedIn::read);
        assertEquals(ex.getMessage(), "Stream closed");

        // Test closing a closed stream.
        try {
            closedIn.close(); // Don't throw exception on double-close.
        } catch (final IOException ioEx) {
            fail("Should not throw exception closing a closed stream.");
        }

        // Test checking a closed stream.
        final OutputStream out = newCryptoOutputStream(transformation, props, baos, key, new IvParameterSpec(iv),
                withChannel);
        out.close();
        // Throw exception.
        assertThrows(IOException.class, ((CryptoOutputStream) out)::checkStream);

        // Test closing a closed stream.
        try {
            out.close(); // Don't throw exception.
        } catch (final IOException ioEx) {
            fail("Should not throw exception closing a closed stream.");
        }

        // Test checkStreamCipher
        try {
            CryptoInputStream.checkStreamCipher(getCipher(cipherClass));
        } catch (final IOException ioEx) {
            assertEquals(ioEx.getMessage(), "AES/CTR/NoPadding is required");
        } finally {
            closedIn.close();
        }

        // Test unsupported operation handling.
        try (final InputStream inNewCrytptoStr = newCryptoInputStream(new ByteArrayInputStream(encData),
                getCipher(cipherClass), defaultBufferSize, iv, false)) {
            closedIn.mark(0);
            assertFalse(closedIn.markSupported());
            ex = assertThrows(IOException.class, inNewCrytptoStr::reset);
            assertEquals(ex.getMessage(), "mark/reset not supported");
        }
    }

    protected void doFieldGetterTest(final String cipherClass, final ByteArrayOutputStream baos,
            final boolean withChannel) throws Exception {
        assumeJniPresence(cipherClass);

        try (final CryptoCipher cipher = getCipher(cipherClass);
                final CryptoInputStream in = newCryptoInputStream(new ByteArrayInputStream(encData), cipher, defaultBufferSize, iv, withChannel)) {

            final Properties props = new Properties();
            final String bufferSize = Integer.toString(defaultBufferSize / 2);
            props.put(CryptoInputStream.STREAM_BUFFER_SIZE_KEY, bufferSize);

            assertEquals(CryptoInputStream.getBufferSize(props), Integer.parseInt(bufferSize));
            assertEquals(in.getBufferSize(), defaultBufferSize);
            assertEquals(in.getCipher().getClass(), Class.forName(cipherClass));
            assertEquals(in.getKey().getAlgorithm(), AES.ALGORITHM);
            assertEquals(in.getParams().getClass(), IvParameterSpec.class);
            assertNotNull(in.getInput());

            try (final CryptoOutputStream out = newCryptoOutputStream(baos, getCipher(cipherClass), defaultBufferSize, iv, withChannel)) {
                assertEquals(out.getOutBuffer().capacity(), defaultBufferSize + cipher.getBlockSize());
                assertEquals(out.getInBuffer().capacity(), defaultBufferSize);
                assertEquals(out.getBufferSize(), defaultBufferSize);
            }
        }
    }

    protected void doReadWriteTest(final int count, final String encCipherClass,
            final String decCipherClass, final byte[] iv) throws IOException {
        doReadWriteTestForInputStream(count, encCipherClass, decCipherClass, iv);
        doReadWriteTestForReadableByteChannel(count, encCipherClass,
                decCipherClass, iv);
    }

    private void doReadWriteTestForInputStream(final int count,
            final String encCipherClass, final String decCipherClass, final byte[] iv)
            throws IOException {
        assumeJniPresence(encCipherClass);
        assumeJniPresence(decCipherClass);
        // Created a cipher object of type encCipherClass;
        try (final CryptoCipher encCipher = getCipher(encCipherClass)) {

            // Generate data
            final SecureRandom random = new SecureRandom();
            final byte[] originalData = new byte[count];
            final byte[] decryptedData = new byte[count];
            random.nextBytes(originalData);

            // Encrypt data
            final ByteArrayOutputStream encryptedData = new ByteArrayOutputStream();
            try (CryptoOutputStream out = newCryptoOutputStream(encryptedData, encCipher, defaultBufferSize, iv, false)) {
                out.write(originalData, 0, originalData.length);
                out.flush();
            }

            // Created a cipher object of type decCipherClass;
            try (final CryptoCipher decCipher = getCipher(decCipherClass)) {

                // Decrypt data
                try (CryptoInputStream in = newCryptoInputStream(new ByteArrayInputStream(encryptedData.toByteArray()), decCipher, defaultBufferSize, iv,
                        false)) {

                    // Check
                    int remainingToRead = count;
                    int offset = 0;
                    while (remainingToRead > 0) {
                        final int n = in.read(decryptedData, offset, decryptedData.length - offset);
                        if (n >= 0) {
                            remainingToRead -= n;
                            offset += n;
                        }
                    }

                    assertArrayEquals(originalData, decryptedData, "originalData and decryptedData not equal");
                }

                // Decrypt data byte-at-a-time
                try (CryptoInputStream in = newCryptoInputStream(new ByteArrayInputStream(encryptedData.toByteArray()), decCipher, defaultBufferSize, iv,
                        false)) {

                    // Check
                    final DataInputStream originalIn = new DataInputStream(new BufferedInputStream(new ByteArrayInputStream(originalData)));
                    int expected;
                    do {
                        expected = originalIn.read();
                        assertEquals(expected, in.read(), "Decrypted stream read by byte does not match");
                    } while (expected != -1);

                    // Completed checking records;
                }
            }
        }
    }

    private void doReadWriteTestForReadableByteChannel(final int count,
            final String encCipherClass, final String decCipherClass, final byte[] iv)
            throws IOException {
        assumeJniPresence(encCipherClass);
        assumeJniPresence(decCipherClass);
        // Creates a cipher object of type encCipherClass;
        try (final CryptoCipher encCipher = getCipher(encCipherClass)) {

            // Generate data
            final SecureRandom random = new SecureRandom();
            final byte[] originalData = new byte[count];
            final byte[] decryptedData = new byte[count];
            random.nextBytes(originalData);

            // Encrypt data
            final ByteArrayOutputStream encryptedData = new ByteArrayOutputStream();
            try (CryptoOutputStream out = newCryptoOutputStream(encryptedData, encCipher, defaultBufferSize, iv, true)) {
                out.write(originalData, 0, originalData.length);
                out.flush();
            }

            // Creates a cipher object of type decCipherClass
            try (final CryptoCipher decCipher = getCipher(decCipherClass)) {

                // Decrypt data
                try (CryptoInputStream in = newCryptoInputStream(new ByteArrayInputStream(encryptedData.toByteArray()), decCipher, defaultBufferSize, iv,
                        true)) {

                    // Check
                    int remainingToRead = count;
                    int offset = 0;
                    while (remainingToRead > 0) {
                        final int n = in.read(decryptedData, offset, decryptedData.length - offset);
                        if (n >= 0) {
                            remainingToRead -= n;
                            offset += n;
                        }
                    }

                    assertArrayEquals(originalData, decryptedData);
                }

                // Decrypt data byte-at-a-time
                try (CryptoInputStream in = newCryptoInputStream(new ByteArrayInputStream(encryptedData.toByteArray()), decCipher, defaultBufferSize, iv,
                        true)) {

                    // Check
                    final DataInputStream originalIn = new DataInputStream(new BufferedInputStream(new ByteArrayInputStream(originalData)));
                    int expected;
                    do {
                        expected = originalIn.read();
                        assertEquals(expected, in.read());
                    } while (expected != -1);

                    // Completed checking records
                }
            }
        }
    }

    protected void doSkipTest(final String cipherClass, final boolean withChannel)
            throws IOException {
        assumeJniPresence(cipherClass);
        try (@SuppressWarnings("resource") // The CryptoCipher returned by getCipherInstance() is closed by CryptoInputStream.
        InputStream in = newCryptoInputStream(
                new ByteArrayInputStream(encData), getCipher(cipherClass),
                defaultBufferSize, iv, withChannel)) {
            final byte[] result = new byte[dataLen];
            final int n1 = readAll(in, result, 0, dataLen / 5);

            assertEquals(in.skip(0), 0);

            long skipped = in.skip(dataLen / 5);
            final int n2 = readAll(in, result, 0, dataLen);

            assertEquals(dataLen, n1 + skipped + n2);
            final byte[] readData = new byte[n2];
            System.arraycopy(result, 0, readData, 0, n2);
            final byte[] expectedData = new byte[n2];
            System.arraycopy(data, dataLen - n2, expectedData, 0, n2);
            assertArrayEquals(readData, expectedData);

            final Exception e = assertThrows(IllegalArgumentException.class, () -> in.skip(-3));
            assertTrue(e.getMessage().contains("Negative skip length"));

            // Skip after EOF
            skipped = in.skip(3);
            assertEquals(skipped, 0);
        }
    }

    protected CryptoCipher getCipher(final String cipherClass) throws IOException {
        try {
            return (CryptoCipher) ReflectionUtils.newInstance(
                    ReflectionUtils.getClassByName(cipherClass), props,
                    transformation);
        } catch (final ClassNotFoundException cnfe) {
            throw new IOException("Illegal crypto cipher!");
        }
    }

    protected CryptoInputStream newCryptoInputStream(final ByteArrayInputStream bais,
            final CryptoCipher cipher, final int bufferSize, final byte[] iv, final boolean withChannel)
            throws IOException {
        if (withChannel) {
            return new CryptoInputStream(Channels.newChannel(bais), cipher,
                    bufferSize, AES.newSecretKeySpec(key),
                    new IvParameterSpec(iv));
        }
        return new CryptoInputStream(bais, cipher, bufferSize,
                AES.newSecretKeySpec(key), new IvParameterSpec(iv));
    }

    protected CryptoInputStream newCryptoInputStream(final String transformation, final Properties props,
    	    final ByteArrayInputStream bais, final byte[] key, final AlgorithmParameterSpec params,
    	    final boolean withChannel) throws IOException {
        if (withChannel) {
    	    return new CryptoInputStream(transformation, props, Channels.newChannel(bais), AES.newSecretKeySpec(key), params);
    	}
        return new CryptoInputStream(transformation, props, bais, AES.newSecretKeySpec(key), params);
    }

    protected CryptoInputStream newCryptoInputStream(final String transformation,
            final Properties props, final ByteArrayInputStream bais, final Key key,
            final AlgorithmParameterSpec params, final boolean withChannel) throws IOException {
        if (withChannel) {
            return new CryptoInputStream(transformation, props, Channels.newChannel(bais), key, params);
        }
        return new CryptoInputStream(transformation, props, bais, key, params);
    }

    protected CryptoOutputStream newCryptoOutputStream(
            final ByteArrayOutputStream baos, final CryptoCipher cipher, final int bufferSize,
            final byte[] iv, final boolean withChannel) throws IOException {
        if (withChannel) {
            return new CryptoOutputStream(Channels.newChannel(baos), cipher,
                    bufferSize, AES.newSecretKeySpec(key),
                    new IvParameterSpec(iv));
        }
        return new CryptoOutputStream(baos, cipher, bufferSize,
                AES.newSecretKeySpec(key), new IvParameterSpec(iv));
    }

    protected CryptoOutputStream newCryptoOutputStream(final String transformation,
            final Properties props, final ByteArrayOutputStream baos, final byte[] key,
            final AlgorithmParameterSpec param, final boolean withChannel) throws IOException {
        if (withChannel) {
            return new CryptoOutputStream(transformation, props, Channels.newChannel(baos),
                    AES.newSecretKeySpec(key), param);
        }
        return new CryptoOutputStream(transformation, props, baos, AES.newSecretKeySpec(key),
                param);
    }

    protected CryptoOutputStream newCryptoOutputStream(final String transformation,
            final Properties props, final ByteArrayOutputStream baos, final Key key,
            final AlgorithmParameterSpec params, final boolean withChannel) throws IOException {
        if (withChannel) {
            return new CryptoOutputStream(transformation, props, Channels.newChannel(baos), key, params);
        }
        return new CryptoOutputStream(transformation, props, baos, key, params);
    }

    private void prepareData() throws IOException, ClassNotFoundException {
        try (CryptoCipher cipher = (CryptoCipher) ReflectionUtils.newInstance(ReflectionUtils.getClassByName(AbstractCipherTest.JCE_CIPHER_CLASSNAME), props,
                transformation)) {
            final ByteArrayOutputStream baos = new ByteArrayOutputStream();
            try (OutputStream out = new CryptoOutputStream(baos, cipher, defaultBufferSize, AES.newSecretKeySpec(key), new IvParameterSpec(iv))) {
                out.write(data);
                out.flush();
            }
            encData = baos.toByteArray();
        }
    }

    private int readAll(final InputStream in, final byte[] b, final int offset, final int len)
            throws IOException {
        int n = 0;
        int total = 0;
        while (n != -1) {
            total += n;
            if (total >= len) {
                break;
            }
            n = in.read(b, offset + total, len - total);
        }

        return total;
    }

    public abstract void setUp() throws IOException;

    /** Test byte buffer read with different buffer size. */
    @Test
    @Timeout(value = 120000, unit = TimeUnit.MILLISECONDS)
    public void testByteBufferRead() throws Exception {
        doByteBufferRead(AbstractCipherTest.JCE_CIPHER_CLASSNAME, false);
        doByteBufferRead(AbstractCipherTest.OPENSSL_CIPHER_CLASSNAME, false);

        doByteBufferRead(AbstractCipherTest.JCE_CIPHER_CLASSNAME, true);
        doByteBufferRead(AbstractCipherTest.OPENSSL_CIPHER_CLASSNAME, true);
    }

    /** Test byte buffer write. */
    @Test
    @Timeout(value = 120000, unit = TimeUnit.MILLISECONDS)
    public void testByteBufferWrite() throws Exception {
        final ByteArrayOutputStream baos = new ByteArrayOutputStream();
        doByteBufferWrite(AbstractCipherTest.JCE_CIPHER_CLASSNAME, baos, false);
        doByteBufferWrite(AbstractCipherTest.OPENSSL_CIPHER_CLASSNAME, baos, false);

        doByteBufferWrite(AbstractCipherTest.JCE_CIPHER_CLASSNAME, baos, true);
        doByteBufferWrite(AbstractCipherTest.OPENSSL_CIPHER_CLASSNAME, baos, true);
    }

    @Test
    @Timeout(value = 120000, unit = TimeUnit.MILLISECONDS)
    public void testExceptions() throws Exception {
        final ByteArrayOutputStream baos = new ByteArrayOutputStream();
        doExceptionTest(AbstractCipherTest.JCE_CIPHER_CLASSNAME, baos, false);
        doExceptionTest(AbstractCipherTest.OPENSSL_CIPHER_CLASSNAME, baos, false);

        doExceptionTest(AbstractCipherTest.JCE_CIPHER_CLASSNAME, baos, true);
        doExceptionTest(AbstractCipherTest.OPENSSL_CIPHER_CLASSNAME, baos, true);
    }

    @Test
    @Timeout(value = 120000, unit = TimeUnit.MILLISECONDS)
    public void testFieldGetters() throws Exception {
        final ByteArrayOutputStream baos = new ByteArrayOutputStream();
        doFieldGetterTest(AbstractCipherTest.JCE_CIPHER_CLASSNAME, baos, false);
        doFieldGetterTest(AbstractCipherTest.OPENSSL_CIPHER_CLASSNAME, baos, false);

        doFieldGetterTest(AbstractCipherTest.JCE_CIPHER_CLASSNAME, baos, true);
        doFieldGetterTest(AbstractCipherTest.OPENSSL_CIPHER_CLASSNAME, baos, true);
    }

    @Test
    public void testReadWrite() throws Exception {
        doReadWriteTest(0, AbstractCipherTest.JCE_CIPHER_CLASSNAME, AbstractCipherTest.JCE_CIPHER_CLASSNAME, iv);
        doReadWriteTest(0, AbstractCipherTest.OPENSSL_CIPHER_CLASSNAME, AbstractCipherTest.OPENSSL_CIPHER_CLASSNAME, iv);
        doReadWriteTest(count, AbstractCipherTest.JCE_CIPHER_CLASSNAME, AbstractCipherTest.JCE_CIPHER_CLASSNAME, iv);
        doReadWriteTest(count, AbstractCipherTest.OPENSSL_CIPHER_CLASSNAME, AbstractCipherTest.OPENSSL_CIPHER_CLASSNAME, iv);
        doReadWriteTest(count, AbstractCipherTest.JCE_CIPHER_CLASSNAME, AbstractCipherTest.OPENSSL_CIPHER_CLASSNAME, iv);
        doReadWriteTest(count, AbstractCipherTest.OPENSSL_CIPHER_CLASSNAME, AbstractCipherTest.JCE_CIPHER_CLASSNAME, iv);
        // Overflow test, IV: xx xx xx xx xx xx xx xx ff ff ff ff ff ff ff ff
        for (int i = 0; i < 8; i++) {
            iv[8 + i] = (byte) 0xff;
        }
        doReadWriteTest(count, AbstractCipherTest.JCE_CIPHER_CLASSNAME, AbstractCipherTest.JCE_CIPHER_CLASSNAME, iv);
        doReadWriteTest(count, AbstractCipherTest.OPENSSL_CIPHER_CLASSNAME, AbstractCipherTest.OPENSSL_CIPHER_CLASSNAME, iv);
        doReadWriteTest(count, AbstractCipherTest.JCE_CIPHER_CLASSNAME, AbstractCipherTest.OPENSSL_CIPHER_CLASSNAME, iv);
        doReadWriteTest(count, AbstractCipherTest.OPENSSL_CIPHER_CLASSNAME, AbstractCipherTest.JCE_CIPHER_CLASSNAME, iv);
    }

    /** Test skip. */
    @Test
    @Timeout(value = 120000, unit = TimeUnit.MILLISECONDS)
    public void testSkip() throws Exception {
        doSkipTest(AbstractCipherTest.JCE_CIPHER_CLASSNAME, false);
        doSkipTest(AbstractCipherTest.OPENSSL_CIPHER_CLASSNAME, false);

        doSkipTest(AbstractCipherTest.JCE_CIPHER_CLASSNAME, true);
        doSkipTest(AbstractCipherTest.OPENSSL_CIPHER_CLASSNAME, true);
    }
}
