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
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.Channels;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Properties;
import java.util.concurrent.TimeUnit;

import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;

import org.apache.commons.crypto.cipher.AbstractCipherTest;
import org.apache.commons.crypto.cipher.CryptoCipher;
import org.apache.commons.crypto.stream.input.ChannelInput;
import org.apache.commons.crypto.stream.input.StreamInput;
import org.apache.commons.crypto.stream.output.ChannelOutput;
import org.apache.commons.crypto.utils.AES;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

public class CtrCryptoStreamTest extends AbstractCipherStreamTest {

    protected void doDecryptTest(final String cipherClass, final boolean withChannel)
            throws IOException {
        try (CryptoCipher cipher = getCipher(cipherClass);
                CtrCryptoInputStream in = newCryptoInputStream(new ByteArrayInputStream(encData), cipher, defaultBufferSize, iv, withChannel)) {

            final ByteBuffer buf = ByteBuffer.allocateDirect(dataLen);
            buf.put(encData);
            buf.rewind();
            in.decrypt(buf, 0, dataLen);
            final byte[] readData = new byte[dataLen];
            final byte[] expectedData = new byte[dataLen];
            buf.get(readData);
            System.arraycopy(data, 0, expectedData, 0, dataLen);
            assertArrayEquals(readData, expectedData);
            final Exception ex = assertThrows(IOException.class, () -> in.decryptBuffer(buf));
            assertEquals(ex.getCause().getClass(), ShortBufferException.class);
        }
    }

    @Override
    protected void doFieldGetterTest(final String cipherClass, final ByteArrayOutputStream baos,
            final boolean withChannel) throws Exception {
        assumeJniPresence(cipherClass);

        final StreamInput streamInput = new StreamInput(new ByteArrayInputStream(encData), 0);
        Exception ex = assertThrows(UnsupportedOperationException.class, () -> streamInput.seek(0));
        assertEquals(ex.getMessage(), "Seek is not supported by this implementation");

        ex = assertThrows(UnsupportedOperationException.class, () -> streamInput.read(0, new byte[0], 0, 0));
        assertEquals(ex.getMessage(), "Positioned read is not supported by this implementation");

        assertEquals(streamInput.available(), encData.length);

        try (ChannelInput channelInput = new ChannelInput(Channels.newChannel(new ByteArrayInputStream(encData)))) {
            ex = assertThrows(UnsupportedOperationException.class, () -> channelInput.seek(0));
            assertEquals(ex.getMessage(), "Seek is not supported by this implementation");

            ex = assertThrows(UnsupportedOperationException.class, () -> channelInput.read(0, new byte[0], 0, 0));
            assertEquals(ex.getMessage(), "Positioned read is not supported by this implementation");
            assertEquals(channelInput.available(), 0);

            final String bufferSize = "4096";
            try (CtrCryptoInputStream in = new CtrCryptoInputStream(channelInput, getCipher(cipherClass), defaultBufferSize, key, iv)) {
                final Properties props = new Properties();
                props.put(CryptoInputStream.STREAM_BUFFER_SIZE_KEY, bufferSize);
                in.setStreamOffset(smallBufferSize);

                assertEquals(CryptoInputStream.getBufferSize(props), Integer.parseInt(bufferSize));
                assertEquals(smallBufferSize, in.getStreamOffset());
                assertEquals(in.getBufferSize(), 8192);
                assertEquals(in.getCipher().getClass(), Class.forName(cipherClass));
                assertEquals(in.getKey().getAlgorithm(), AES.ALGORITHM);
                assertEquals(in.getParams().getClass(), IvParameterSpec.class);
                assertNotNull(in.getInput());
            }

            try (CryptoCipher cipher = getCipher(cipherClass);
                    CtrCryptoOutputStream out = new CtrCryptoOutputStream(new ChannelOutput(Channels.newChannel(baos)), cipher, Integer.parseInt(bufferSize),
                            key, iv)) {
                out.setStreamOffset(smallBufferSize);
                assertEquals(out.getStreamOffset(), smallBufferSize);
            }
        }
    }

    @Override
    protected CtrCryptoInputStream newCryptoInputStream(
            final ByteArrayInputStream bais, final CryptoCipher cipher, final int bufferSize,
            final byte[] iv, final boolean withChannel) throws IOException {
        if (withChannel) {
            return new CtrCryptoInputStream(Channels.newChannel(bais), cipher,
                    bufferSize, key, iv);
        }
        return new CtrCryptoInputStream(bais, cipher, bufferSize, key, iv);
    }

    @Override
    protected CryptoInputStream newCryptoInputStream(final String transformation, final Properties props,
            final ByteArrayInputStream bais, final byte[] key, final AlgorithmParameterSpec params,
            final boolean withChannel) throws IOException {
        if (withChannel) {
            return new CtrCryptoInputStream(props, Channels.newChannel(bais), key,
                    ((IvParameterSpec)params).getIV());
        }
        return new CtrCryptoInputStream(props, bais, key, ((IvParameterSpec)params).getIV());
    }

    @Override
    protected CtrCryptoOutputStream newCryptoOutputStream(
            final ByteArrayOutputStream baos, final CryptoCipher cipher, final int bufferSize,
            final byte[] iv, final boolean withChannel) throws IOException {
        if (withChannel) {
            return new CtrCryptoOutputStream(Channels.newChannel(baos), cipher,
                    bufferSize, key, iv);
        }
        return new CtrCryptoOutputStream(baos, cipher, bufferSize, key, iv);
    }

    @Override
    protected CtrCryptoOutputStream newCryptoOutputStream(final String transformation,
            final Properties props, final ByteArrayOutputStream baos, final byte[] key,
            final AlgorithmParameterSpec params, final boolean withChannel) throws IOException {
        if (withChannel) {
            return new CtrCryptoOutputStream(props, Channels.newChannel(baos), key,
                    ((IvParameterSpec)params).getIV());
        }
        return new CtrCryptoOutputStream(props, baos, key, ((IvParameterSpec)params).getIV());
    }

    @Override
    public void setUp() {
        transformation = AES.CTR_NO_PADDING;
    }

    @Test
    @Timeout(value = 120000, unit = TimeUnit.MILLISECONDS)
    public void testDecrypt() throws Exception {
        doDecryptTest(AbstractCipherTest.JCE_CIPHER_CLASSNAME, false);
        doDecryptTest(AbstractCipherTest.OPENSSL_CIPHER_CLASSNAME, false);

        doDecryptTest(AbstractCipherTest.JCE_CIPHER_CLASSNAME, true);
        doDecryptTest(AbstractCipherTest.OPENSSL_CIPHER_CLASSNAME, true);
    }
}
