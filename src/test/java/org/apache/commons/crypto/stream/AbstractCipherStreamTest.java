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

import static org.junit.Assert.assertEquals;

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

import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.crypto.Crypto;
import org.apache.commons.crypto.cipher.AbstractCipherTest;
import org.apache.commons.crypto.cipher.CryptoCipher;
import org.apache.commons.crypto.utils.ReflectionUtils;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

public abstract class AbstractCipherStreamTest {

    protected final int dataLen = 20000;
    protected final byte[] data = new byte[dataLen];
    protected byte[] encData;
    private final Properties props = new Properties();
    protected byte[] key = new byte[16];
    protected byte[] iv = new byte[16];
    protected int count = 10000;
    protected static int defaultBufferSize = 8192;
    protected static int smallBufferSize = 1024;

    protected String transformation;

    public abstract void setUp() throws IOException;

    @Before
    public void before() throws IOException {
        final Random random = new SecureRandom();
        random.nextBytes(data);
        random.nextBytes(key);
        random.nextBytes(iv);
        setUp();
        prepareData();
    }

    /** Test skip. */
    @Test(timeout = 120000)
    public void testSkip() throws Exception {
        doSkipTest(AbstractCipherTest.JCE_CIPHER_CLASSNAME, false);
        doSkipTest(AbstractCipherTest.OPENSSL_CIPHER_CLASSNAME, false);

        doSkipTest(AbstractCipherTest.JCE_CIPHER_CLASSNAME, true);
        doSkipTest(AbstractCipherTest.OPENSSL_CIPHER_CLASSNAME, true);
    }

    /** Test byte buffer read with different buffer size. */
    @Test(timeout = 120000)
    public void testByteBufferRead() throws Exception {
        doByteBufferRead(AbstractCipherTest.JCE_CIPHER_CLASSNAME, false);
        doByteBufferRead(AbstractCipherTest.OPENSSL_CIPHER_CLASSNAME, false);

        doByteBufferRead(AbstractCipherTest.JCE_CIPHER_CLASSNAME, true);
        doByteBufferRead(AbstractCipherTest.OPENSSL_CIPHER_CLASSNAME, true);
    }

    /** Test byte buffer write. */
    @Test(timeout = 120000)
    public void testByteBufferWrite() throws Exception {
        final ByteArrayOutputStream baos = new ByteArrayOutputStream();
        doByteBufferWrite(AbstractCipherTest.JCE_CIPHER_CLASSNAME, baos, false);
        doByteBufferWrite(AbstractCipherTest.OPENSSL_CIPHER_CLASSNAME, baos, false);

        doByteBufferWrite(AbstractCipherTest.JCE_CIPHER_CLASSNAME, baos, true);
        doByteBufferWrite(AbstractCipherTest.OPENSSL_CIPHER_CLASSNAME, baos, true);
    }

    @Test(timeout = 120000)
    public void testExceptions() throws Exception {
        final ByteArrayOutputStream baos = new ByteArrayOutputStream();
        doExceptionTest(AbstractCipherTest.JCE_CIPHER_CLASSNAME, baos, false);
        doExceptionTest(AbstractCipherTest.OPENSSL_CIPHER_CLASSNAME, baos, false);

        doExceptionTest(AbstractCipherTest.JCE_CIPHER_CLASSNAME, baos, true);
        doExceptionTest(AbstractCipherTest.OPENSSL_CIPHER_CLASSNAME, baos, true);
    }

    @Test(timeout = 120000)
    public void testFieldGetters() throws Exception {
        final ByteArrayOutputStream baos = new ByteArrayOutputStream();
        doFieldGetterTest(AbstractCipherTest.JCE_CIPHER_CLASSNAME, baos, false);
        doFieldGetterTest(AbstractCipherTest.OPENSSL_CIPHER_CLASSNAME, baos, false);

        doFieldGetterTest(AbstractCipherTest.JCE_CIPHER_CLASSNAME, baos, true);
        doFieldGetterTest(AbstractCipherTest.OPENSSL_CIPHER_CLASSNAME, baos, true);
    }

    protected void doSkipTest(final String cipherClass, final boolean withChannel)
            throws IOException {
        if (AbstractCipherTest.OPENSSL_CIPHER_CLASSNAME.equals(cipherClass)) {
            if (!Crypto.isNativeCodeLoaded()) {
                return; // Skip this test if no JNI
            }
        }
        try (InputStream in = getCryptoInputStream(
                new ByteArrayInputStream(encData), getCipher(cipherClass),
                defaultBufferSize, iv, withChannel)) {
            final byte[] result = new byte[dataLen];
            final int n1 = readAll(in, result, 0, dataLen / 5);

            Assert.assertEquals(in.skip(0), 0);

            long skipped = in.skip(dataLen / 5);
            final int n2 = readAll(in, result, 0, dataLen);

            Assert.assertEquals(dataLen, n1 + skipped + n2);
            final byte[] readData = new byte[n2];
            System.arraycopy(result, 0, readData, 0, n2);
            final byte[] expectedData = new byte[n2];
            System.arraycopy(data, dataLen - n2, expectedData, 0, n2);
            Assert.assertArrayEquals(readData, expectedData);

            try {
                skipped = in.skip(-3);
                Assert.fail("Skip Negative length should fail.");
            } catch (final IllegalArgumentException e) {
                Assert.assertTrue(e.getMessage().contains("Negative skip length"));
            }

            // Skip after EOF
            skipped = in.skip(3);
            Assert.assertEquals(skipped, 0);
        }
    }

    protected void doByteBufferRead(final String cipherClass, final boolean withChannel)
        throws Exception {
        if (AbstractCipherTest.OPENSSL_CIPHER_CLASSNAME.equals(cipherClass)) {
            if (!Crypto.isNativeCodeLoaded()) {
                return; // Skip this test if no JNI
            }
        }
        ByteBuffer buf = ByteBuffer.allocate(dataLen + 100);
        // Default buffer size, initial buffer position is 0
        try (InputStream in = getCryptoInputStream(new ByteArrayInputStream(encData), getCipher(cipherClass),
            defaultBufferSize, iv, withChannel)) {
            byteBufferReadCheck(in, buf, 0);
        }

        // Default buffer size, initial buffer position is not 0
        try (InputStream in = getCryptoInputStream(new ByteArrayInputStream(encData), getCipher(cipherClass),
            defaultBufferSize, iv, withChannel)) {
            buf.clear();
            byteBufferReadCheck(in, buf, 11);
        }

        // Small buffer size, initial buffer position is 0
        try (InputStream in = getCryptoInputStream(new ByteArrayInputStream(encData), getCipher(cipherClass),
            smallBufferSize, iv, withChannel)) {
            buf.clear();
            byteBufferReadCheck(in, buf, 0);
        }

        // Small buffer size, initial buffer position is not 0
        try (InputStream in = getCryptoInputStream(new ByteArrayInputStream(encData), getCipher(cipherClass),
            smallBufferSize, iv, withChannel)) {
            buf.clear();
            byteBufferReadCheck(in, buf, 11);
        }

        // Direct buffer, default buffer size, initial buffer position is 0
        try (InputStream in = getCryptoInputStream(new ByteArrayInputStream(encData), getCipher(cipherClass),
            defaultBufferSize, iv, withChannel)) {
            buf = ByteBuffer.allocateDirect(dataLen + 100);
            byteBufferReadCheck(in, buf, 0);
        }

        // Direct buffer, default buffer size, initial buffer position is not 0
        try (InputStream in = getCryptoInputStream(new ByteArrayInputStream(encData), getCipher(cipherClass),
            defaultBufferSize, iv, withChannel)) {
            buf.clear();
            byteBufferReadCheck(in, buf, 11);
        }

        // Direct buffer, small buffer size, initial buffer position is 0
        try (InputStream in = getCryptoInputStream(new ByteArrayInputStream(encData), getCipher(cipherClass),
            smallBufferSize, iv, withChannel)) {
            buf.clear();
            byteBufferReadCheck(in, buf, 0);
        }

        // Direct buffer, small buffer size, initial buffer position is not 0
        try (InputStream in = getCryptoInputStream(new ByteArrayInputStream(encData), getCipher(cipherClass),
            smallBufferSize, iv, withChannel)) {
            buf.clear();
            byteBufferReadCheck(in, buf, 11);
        }

        // Direct buffer, small buffer size, initial buffer position is 0, final read
        try (InputStream in = getCryptoInputStream(new ByteArrayInputStream(encData), getCipher(cipherClass),
            smallBufferSize, iv, withChannel)) {
            buf.clear();
            byteBufferFinalReadCheck(in, buf, 0);
        }

        // Default buffer size, initial buffer position is 0, insufficient dest buffer length
        try (InputStream in = getCryptoInputStream(new ByteArrayInputStream(encData), getCipher(cipherClass),
            defaultBufferSize, iv, withChannel)) {
            buf = ByteBuffer.allocate(100);
            byteBufferReadCheck(in, buf, 0);
        }

        // Default buffer size, initial buffer position is 0
        try (InputStream in = getCryptoInputStream(transformation, props, new ByteArrayInputStream(encData), key,
            new IvParameterSpec(iv), withChannel)) {
            buf = ByteBuffer.allocate(dataLen + 100);
            byteBufferReadCheck(in, buf, 0);
        }

        // Default buffer size, initial buffer position is not 0
        try (InputStream in = getCryptoInputStream(transformation, props, new ByteArrayInputStream(encData), key,
            new IvParameterSpec(iv), withChannel)) {
            buf.clear();
            byteBufferReadCheck(in, buf, 11);
        }

        // Small buffer size, initial buffer position is 0
        try (InputStream in = getCryptoInputStream(transformation, props, new ByteArrayInputStream(encData), key,
            new IvParameterSpec(iv), withChannel)) {
            buf.clear();
            byteBufferReadCheck(in, buf, 0);
        }

        // Small buffer size, initial buffer position is not 0
        try (InputStream in = getCryptoInputStream(transformation, props, new ByteArrayInputStream(encData), key,
            new IvParameterSpec(iv), withChannel)) {
            buf.clear();
            byteBufferReadCheck(in, buf, 11);
        }

        // Direct buffer, default buffer size, initial buffer position is 0
        try (InputStream in = getCryptoInputStream(transformation, props, new ByteArrayInputStream(encData), key,
            new IvParameterSpec(iv), withChannel)) {
            buf = ByteBuffer.allocateDirect(dataLen + 100);
            byteBufferReadCheck(in, buf, 0);
        }

        // Direct buffer, default buffer size, initial buffer position is not 0
        try (InputStream in = getCryptoInputStream(transformation, props, new ByteArrayInputStream(encData), key,
            new IvParameterSpec(iv), withChannel)) {
            buf.clear();
            byteBufferReadCheck(in, buf, 11);
        }

        // Direct buffer, small buffer size, initial buffer position is 0
        try (InputStream in = getCryptoInputStream(transformation, props, new ByteArrayInputStream(encData), key,
            new IvParameterSpec(iv), withChannel)) {
            buf.clear();
            byteBufferReadCheck(in, buf, 0);
        }

        // Direct buffer, small buffer size, initial buffer position is not 0
        try (InputStream in = getCryptoInputStream(transformation, props, new ByteArrayInputStream(encData), key,
            new IvParameterSpec(iv), withChannel)) {
            buf.clear();
            byteBufferReadCheck(in, buf, 11);
        }

        // Direct buffer, default buffer size, initial buffer position is 0, final read
        try (InputStream in = getCryptoInputStream(transformation, props, new ByteArrayInputStream(encData), key,
            new IvParameterSpec(iv), withChannel)) {
            buf.clear();
            byteBufferFinalReadCheck(in, buf, 0);
        }

        // Default buffer size, initial buffer position is 0, insufficient dest buffer length
        try (InputStream in = getCryptoInputStream(transformation, props, new ByteArrayInputStream(encData), key,
            new IvParameterSpec(iv), withChannel)) {
            buf = ByteBuffer.allocate(100);
            byteBufferReadCheck(in, buf, 0);
        }
    }

    protected void doByteBufferWrite(final String cipherClass,
            final ByteArrayOutputStream baos, final boolean withChannel)
                throws Exception {
        if (AbstractCipherTest.OPENSSL_CIPHER_CLASSNAME.equals(cipherClass)) {
            if (!Crypto.isNativeCodeLoaded()) {
                return; // Skip this test if no JNI
            }
        }
        baos.reset();
        CryptoOutputStream out = getCryptoOutputStream(baos,
                getCipher(cipherClass), defaultBufferSize, iv, withChannel);
        doByteBufferWrite(out, withChannel);

        baos.reset();
        final CryptoCipher cipher = getCipher(cipherClass);
        final String transformation = cipher.getAlgorithm();
        out = getCryptoOutputStream(transformation, props, baos, key,
                new IvParameterSpec(iv), withChannel);
        doByteBufferWrite(out, withChannel);
        out.write(1);
        Assert.assertTrue(out.isOpen());

        out = getCryptoOutputStream(transformation, props, baos, key,
                new IvParameterSpec(iv), withChannel);
        out.close();
        Assert.assertTrue(!out.isOpen());
    }

    protected void doExceptionTest(final String cipherClass, final ByteArrayOutputStream baos,
            final boolean withChannel) throws IOException {
        if (AbstractCipherTest.OPENSSL_CIPHER_CLASSNAME.equals(cipherClass)) {
            if (!Crypto.isNativeCodeLoaded()) {
                return; // Skip this test if no JNI
            }
        }

        InputStream in = null;
        OutputStream out = null;

        // Test InvalidAlgorithmParameters
        try {
        	in = getCryptoInputStream(transformation, props, new ByteArrayInputStream(encData),
                    new SecretKeySpec(key, "AES"), new GCMParameterSpec(0, new byte[0]),
                    withChannel);
            Assert.fail("Expected IOException.");
        } catch (final IOException ex) {
            Assert.assertEquals(ex.getMessage(),"Illegal parameters");
        }

        // Test InvalidAlgorithmParameters
        try {
            out = getCryptoOutputStream(transformation, props, baos,
                    new SecretKeySpec(key, "AES"), new GCMParameterSpec(0,
                    new byte[0]), withChannel);
            Assert.fail("Expected IOException.");
        } catch (final IOException ex) {
        	Assert.assertEquals(ex.getMessage(),"Illegal parameters");
        }

        // Test Invalid Key
        try {
            in = getCryptoInputStream(transformation,props, new ByteArrayInputStream(encData),
                    new SecretKeySpec(new byte[10], "AES"), new IvParameterSpec(iv), withChannel);
            Assert.fail("Expected IOException for Invalid Key");
        } catch (final IOException ex) {
            Assert.assertNotNull(ex);
        }

        // Test Invalid Key
        try {
            out = getCryptoOutputStream(transformation, props, baos, new byte[10],
                    new IvParameterSpec(iv), withChannel);
            Assert.fail("Expected IOException for Invalid Key");
        } catch (final IOException ex) {
            Assert.assertNotNull(ex);
        }

        // Test reading a closed stream.
        try {
            in = getCryptoInputStream(new ByteArrayInputStream(encData),
                    getCipher(cipherClass), defaultBufferSize, iv, withChannel);
            in.close();
            in.read(); // Throw exception.
        } catch (final IOException ex) {
            Assert.assertTrue(ex.getMessage().equals("Stream closed"));
        }

        // Test closing a closed stream.
        try {
            in.close(); // Don't throw exception on double-close.
        } catch (final IOException ex) {
            Assert.fail("Should not throw exception closing a closed stream.");
        }

        // Test checking a closed stream.
        try {
            out = getCryptoOutputStream(transformation, props, baos, key, new IvParameterSpec(iv),
                    withChannel);
            out.close();
            ((CryptoOutputStream)out).checkStream(); // Throw exception.
        } catch (final IOException ex) {
            Assert.assertTrue(ex.getMessage().equals("Stream closed"));
        }

        // Test closing a closed stream.
        try {
            out.close(); // Don't throw exception.
        } catch (final IOException ex) {
            Assert.fail("Should not throw exception closing a closed stream.");
        }

        // Test checkStreamCipher
        try {
            CryptoInputStream.checkStreamCipher(getCipher(cipherClass));
        } catch (final IOException ex) {
            Assert.assertTrue(ex.getMessage().equals("AES/CTR/NoPadding is required"));
        } finally {
            in.close();
        }

        // Test unsupported operation handling.
        try {
            in = getCryptoInputStream(new ByteArrayInputStream(encData),
                    getCipher(cipherClass), defaultBufferSize, iv, false);
            in.mark(0);
            assertEquals(false, in.markSupported());
            in.reset();
            Assert.fail("Expected IOException.");
        } catch (final IOException ex) {
            Assert.assertTrue(ex.getMessage().equals("Mark/reset not supported"));
        } finally {
            in.close();
        }
    }

    protected void doFieldGetterTest(final String cipherClass, final ByteArrayOutputStream baos,
            final boolean withChannel) throws Exception {
        if (AbstractCipherTest.OPENSSL_CIPHER_CLASSNAME.equals(cipherClass)) {
            if (!Crypto.isNativeCodeLoaded()) {
                return; // Skip this test if no JNI
            }
        }

        final CryptoCipher cipher = getCipher(cipherClass);

        final CryptoInputStream in = getCryptoInputStream(
                new ByteArrayInputStream(encData), cipher, defaultBufferSize,
                iv, withChannel);

        final Properties props = new Properties();
        final String bufferSize = Integer.toString(defaultBufferSize / 2);
        props.put(CryptoInputStream.STREAM_BUFFER_SIZE_KEY, bufferSize);

        Assert.assertEquals(CryptoInputStream.getBufferSize(props), Integer.parseInt(bufferSize));
        Assert.assertEquals(in.getBufferSize(), defaultBufferSize);
        Assert.assertEquals(in.getCipher().getClass(), Class.forName(cipherClass));
        Assert.assertEquals(in.getKey().getAlgorithm(), "AES");
        Assert.assertEquals(in.getParams().getClass(), IvParameterSpec.class);
        Assert.assertNotNull(in.getInput());

        final CryptoOutputStream out = getCryptoOutputStream(baos, getCipher(cipherClass),
                defaultBufferSize, iv, withChannel);

        Assert.assertEquals(out.getOutBuffer().capacity(), defaultBufferSize + cipher.getBlockSize());
        Assert.assertEquals(out.getInBuffer().capacity(), defaultBufferSize);
        Assert.assertEquals(out.getBufferSize(), defaultBufferSize);
    }

    private void byteBufferReadCheck(final InputStream in, final ByteBuffer buf, final int bufPos)
            throws Exception {
        buf.position(bufPos);
        final int n = ((ReadableByteChannel) in).read(buf);
        Assert.assertEquals(bufPos + n, buf.position());
        final byte[] readData = new byte[n];
        buf.rewind();
        buf.position(bufPos);
        buf.get(readData);
        final byte[] expectedData = new byte[n];
        System.arraycopy(data, 0, expectedData, 0, n);
        Assert.assertArrayEquals(readData, expectedData);

        try {
            in.read(readData, -1, 0);
            Assert.fail("Expected IndexOutOfBoundsException.");
        } catch (final IndexOutOfBoundsException ex) {
            Assert.assertNotNull(ex);
        }
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
        Assert.assertArrayEquals(readData, expectedData);
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
        try (OutputStream out = new CryptoOutputStream(baos, cipher,
                defaultBufferSize, new SecretKeySpec(key, "AES"),
                new IvParameterSpec(iv))) {
            out.write(data);
            out.flush();
        }
        encData = baos.toByteArray();
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

        Assert.assertEquals(dataLen, n1 + n2 + n3 + 1);

        try {
            out.write(data, 0, data.length + 1);
            Assert.fail("Expected IndexOutOfBoundsException.");
        } catch (final IndexOutOfBoundsException ex) {
            Assert.assertNotNull(ex);
        }

        out.flush();

        try (InputStream in = getCryptoInputStream(
                new ByteArrayInputStream(encData), out.getCipher(),
                defaultBufferSize, iv, withChannel)) {
            buf = ByteBuffer.allocate(dataLen + 100);
            byteBufferReadCheck(in, buf, 0);
        }
    }

    protected CryptoInputStream getCryptoInputStream(final ByteArrayInputStream bais,
            final CryptoCipher cipher, final int bufferSize, final byte[] iv, final boolean withChannel)
            throws IOException {
        if (withChannel) {
            return new CryptoInputStream(Channels.newChannel(bais), cipher,
                    bufferSize, new SecretKeySpec(key, "AES"),
                    new IvParameterSpec(iv));
        }
        return new CryptoInputStream(bais, cipher, bufferSize,
                new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
    }

    protected CryptoInputStream getCryptoInputStream(final String transformation, final Properties props,
    	    final ByteArrayInputStream bais, final byte[] key, final AlgorithmParameterSpec params,
    	    final boolean withChannel) throws IOException {
        if (withChannel) {
    	    return new CryptoInputStream(transformation, props, Channels.newChannel(bais), new SecretKeySpec(key, "AES"), params);
    	}
        return new CryptoInputStream(transformation, props, bais, new SecretKeySpec(key, "AES"), params);
    }

    protected CryptoInputStream getCryptoInputStream(final String transformation,
            final Properties props, final ByteArrayInputStream bais, final Key key,
            final AlgorithmParameterSpec params, final boolean withChannel) throws IOException {
        if (withChannel) {
            return new CryptoInputStream(transformation, props, Channels.newChannel(bais), key, params);
        }
        return new CryptoInputStream(transformation, props, bais, key, params);
    }

    protected CryptoOutputStream getCryptoOutputStream(
            final ByteArrayOutputStream baos, final CryptoCipher cipher, final int bufferSize,
            final byte[] iv, final boolean withChannel) throws IOException {
        if (withChannel) {
            return new CryptoOutputStream(Channels.newChannel(baos), cipher,
                    bufferSize, new SecretKeySpec(key, "AES"),
                    new IvParameterSpec(iv));
        }
        return new CryptoOutputStream(baos, cipher, bufferSize,
                new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
    }

    protected CryptoOutputStream getCryptoOutputStream(final String transformation,
            final Properties props, final ByteArrayOutputStream baos, final byte[] key,
            final AlgorithmParameterSpec param, final boolean withChannel) throws IOException {
        if (withChannel) {
            return new CryptoOutputStream(transformation, props, Channels.newChannel(baos),
                    new SecretKeySpec(key, "AES"), param);
        }
        return new CryptoOutputStream(transformation, props, baos, new SecretKeySpec(key, "AES"),
                param);
    }

    protected CryptoOutputStream getCryptoOutputStream(final String transformation,
            final Properties props, final ByteArrayOutputStream baos, final Key key,
            final AlgorithmParameterSpec params, final boolean withChannel) throws IOException {
        if (withChannel) {
            return new CryptoOutputStream(transformation, props, Channels.newChannel(baos), key, params);
        }
        return new CryptoOutputStream(transformation, props, baos, key, params);
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

    protected CryptoCipher getCipher(final String cipherClass) throws IOException {
        try {
            return (CryptoCipher) ReflectionUtils.newInstance(
                    ReflectionUtils.getClassByName(cipherClass), props,
                    transformation);
        } catch (final ClassNotFoundException cnfe) {
            throw new IOException("Illegal crypto cipher!");
        }
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

    protected void doReadWriteTest(final int count, final String encCipherClass,
            final String decCipherClass, final byte[] iv) throws IOException {
        doReadWriteTestForInputStream(count, encCipherClass, decCipherClass, iv);
        doReadWriteTestForReadableByteChannel(count, encCipherClass,
                decCipherClass, iv);
    }

    private void doReadWriteTestForInputStream(final int count,
            final String encCipherClass, final String decCipherClass, final byte[] iv)
            throws IOException {
        if (AbstractCipherTest.OPENSSL_CIPHER_CLASSNAME.equals(encCipherClass)
                ||
            AbstractCipherTest.OPENSSL_CIPHER_CLASSNAME.equals(decCipherClass)) {
            if (!Crypto.isNativeCodeLoaded()) {
                return; // Skip this test if no JNI
            }
        }
        // Created a cipher object of type encCipherClass;
        final CryptoCipher encCipher = getCipher(encCipherClass);

        // Generate data
        final SecureRandom random = new SecureRandom();
        final byte[] originalData = new byte[count];
        final byte[] decryptedData = new byte[count];
        random.nextBytes(originalData);

        // Encrypt data
        final ByteArrayOutputStream encryptedData = new ByteArrayOutputStream();
        try (CryptoOutputStream out = getCryptoOutputStream(encryptedData,
                encCipher, defaultBufferSize, iv, false)) {
            out.write(originalData, 0, originalData.length);
            out.flush();
        }

        // Created a cipher object of type decCipherClass;
        final CryptoCipher decCipher = getCipher(decCipherClass);

        // Decrypt data
        CryptoInputStream in = getCryptoInputStream(new ByteArrayInputStream(
                encryptedData.toByteArray()), decCipher, defaultBufferSize, iv,
                false);

        // Check
        int remainingToRead = count;
        int offset = 0;
        while (remainingToRead > 0) {
            final int n = in.read(decryptedData, offset, decryptedData.length
                    - offset);
            if (n >= 0) {
                remainingToRead -= n;
                offset += n;
            }
        }

        Assert.assertArrayEquals("originalData and decryptedData not equal",
                originalData, decryptedData);

        // Decrypt data byte-at-a-time
        in = getCryptoInputStream(
                new ByteArrayInputStream(encryptedData.toByteArray()),
                decCipher, defaultBufferSize, iv, false);

        // Check
        final DataInputStream originalIn = new DataInputStream(
                new BufferedInputStream(new ByteArrayInputStream(originalData)));
        int expected;
        do {
            expected = originalIn.read();
            Assert.assertEquals("Decrypted stream read by byte does not match",
                    expected, in.read());
        } while (expected != -1);

        // Completed checking records;
    }

    private void doReadWriteTestForReadableByteChannel(final int count,
            final String encCipherClass, final String decCipherClass, final byte[] iv)
            throws IOException {
        if (AbstractCipherTest.OPENSSL_CIPHER_CLASSNAME.equals(encCipherClass)
                ||
            AbstractCipherTest.OPENSSL_CIPHER_CLASSNAME.equals(decCipherClass)) {
            if (!Crypto.isNativeCodeLoaded()) {
                return; // Skip this test if no JNI
            }
        }
        // Creates a cipher object of type encCipherClass;
        final CryptoCipher encCipher = getCipher(encCipherClass);

        // Generate data
        final SecureRandom random = new SecureRandom();
        final byte[] originalData = new byte[count];
        final byte[] decryptedData = new byte[count];
        random.nextBytes(originalData);

        // Encrypt data
        final ByteArrayOutputStream encryptedData = new ByteArrayOutputStream();
        try (CryptoOutputStream out = getCryptoOutputStream(encryptedData,
                encCipher, defaultBufferSize, iv, true)) {
            out.write(originalData, 0, originalData.length);
            out.flush();
        }

        // Creates a cipher object of type decCipherClass
        final CryptoCipher decCipher = getCipher(decCipherClass);

        // Decrypt data
        CryptoInputStream in = getCryptoInputStream(new ByteArrayInputStream(
                encryptedData.toByteArray()), decCipher, defaultBufferSize, iv,
                true);

        // Check
        int remainingToRead = count;
        int offset = 0;
        while (remainingToRead > 0) {
            final int n = in.read(decryptedData, offset, decryptedData.length
                    - offset);
            if (n >= 0) {
                remainingToRead -= n;
                offset += n;
            }
        }

        Assert.assertArrayEquals("originalData and decryptedData not equal",
                originalData, decryptedData);

        // Decrypt data byte-at-a-time
        in = getCryptoInputStream(
                new ByteArrayInputStream(encryptedData.toByteArray()),
                decCipher, defaultBufferSize, iv, true);

        // Check
        final DataInputStream originalIn = new DataInputStream(
                new BufferedInputStream(new ByteArrayInputStream(originalData)));
        int expected;
        do {
            expected = originalIn.read();
            Assert.assertEquals("Decrypted stream read by byte does not match",
                    expected, in.read());
        } while (expected != -1);

        // Completed checking records
    }
}
