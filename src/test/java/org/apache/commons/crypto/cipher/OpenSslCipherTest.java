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

package org.apache.commons.crypto.cipher;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Properties;
import java.util.concurrent.TimeUnit;

import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;

import org.apache.commons.crypto.utils.AES;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;


public class OpenSslCipherTest extends AbstractCipherTest {

    private ByteBuffer dummyBuffer() {
        return ByteBuffer.allocateDirect(8);
    }

    @Override
    public void init() {
        assumeTrue(OpenSsl.getLoadingFailureReason() == null);
        transformations = new String[] {
                AES.CBC_NO_PADDING,
                AES.CBC_PKCS5_PADDING,
                AES.CTR_NO_PADDING};
        cipherClass = OPENSSL_CIPHER_CLASSNAME;
    }

    @Test
    public void testCipherLifecycle() throws Exception {
        try (OpenSslCipher cipher = new OpenSslCipher(new Properties(), AES.CTR_NO_PADDING)) {

            assertThrows(IllegalStateException.class, () -> cipher.update(dummyBuffer(), dummyBuffer()));
            cipher.init(OpenSsl.ENCRYPT_MODE, AES.newSecretKeySpec(KEY),
                new IvParameterSpec(IV));
            cipher.update(dummyBuffer(), dummyBuffer());

            assertThrows(InvalidKeyException.class, () -> cipher.init(OpenSsl.ENCRYPT_MODE, AES.newSecretKeySpec(new byte[1]),
                    new IvParameterSpec(IV)));
            // Should keep working with previous init parameters.
            cipher.update(dummyBuffer(), dummyBuffer());
            cipher.doFinal(dummyBuffer(), dummyBuffer());
            cipher.close();

            assertThrows(IllegalStateException.class, () -> cipher.update(dummyBuffer(), dummyBuffer()));
            cipher.init(OpenSsl.ENCRYPT_MODE, AES.newSecretKeySpec(KEY),
                new IvParameterSpec(IV));
            cipher.update(dummyBuffer(), dummyBuffer());
        }
    }

    @Test
    @Timeout(value = 120000, unit = TimeUnit.MILLISECONDS)
    public void testDoFinalArguments() throws Exception {
        assumeTrue(OpenSsl.getLoadingFailureReason() == null);
        final OpenSsl cipher = OpenSsl
                .getInstance(AES.CTR_NO_PADDING);
        assertNotNull(cipher);

        cipher.init(OpenSsl.ENCRYPT_MODE, KEY, new IvParameterSpec(IV));

        // Require direct buffer
        final ByteBuffer input = ByteBuffer.allocate(1024);
        final ByteBuffer output = ByteBuffer.allocate(1024);

        final Exception ex = assertThrows(IllegalArgumentException.class, () -> cipher.doFinal(input, output));
        assertTrue(ex.getMessage().contains("Direct buffer is required"));
    }

    @Override
    @Test
    @Timeout(value = 120000, unit = TimeUnit.MILLISECONDS)
    public void testInvalidIV() throws Exception {
        assumeTrue(OpenSsl.getLoadingFailureReason() == null);
        final OpenSsl cipher = OpenSsl
                .getInstance(AES.CTR_NO_PADDING);
        assertNotNull(cipher);

        final byte[] invalidIV = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
                0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x11 };

        assertThrows(InvalidAlgorithmParameterException.class,
                () -> cipher.init(OpenSsl.ENCRYPT_MODE, KEY, new IvParameterSpec(invalidIV)));
    }

    @Override
    @Test
    @Timeout(value = 120000, unit = TimeUnit.MILLISECONDS)
    public void testInvalidIVClass() throws Exception {
        final OpenSsl cipher = OpenSsl.getInstance(AES.CTR_NO_PADDING);
        assertNotNull(cipher);


        assertThrows(InvalidAlgorithmParameterException.class,
                () ->  cipher.init(OpenSsl.ENCRYPT_MODE, KEY, new GCMParameterSpec(IV.length, IV)));
    }

    @Override
    @Test
    @Timeout(value = 120000, unit = TimeUnit.MILLISECONDS)
    public void testInvalidKey() throws Exception {
        assumeTrue(OpenSsl.getLoadingFailureReason() == null);
        final OpenSsl cipher = OpenSsl
                .getInstance(AES.CTR_NO_PADDING);
        assertNotNull(cipher);

        final byte[] invalidKey = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
                0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x11 };

        assertThrows(InvalidKeyException.class,
                () -> cipher.init(OpenSsl.ENCRYPT_MODE, invalidKey, new IvParameterSpec(IV)));
    }

    @Test
    @Timeout(value = 120000, unit = TimeUnit.MILLISECONDS)
    public void testInvalidMode() {
        assumeTrue(OpenSsl.getLoadingFailureReason() == null);
        assertThrows(NoSuchAlgorithmException.class,
                () -> OpenSsl.getInstance("AES/CTR2/NoPadding"));
    }

    @Test
    @Timeout(value = 120000, unit = TimeUnit.MILLISECONDS)
    public void testInvalidPadding() {
        assumeTrue(OpenSsl.getLoadingFailureReason() == null);
        assertThrows(NoSuchPaddingException.class,
                () -> OpenSsl.getInstance("AES/CTR/NoPadding2"));
    }

    @Test
    @Timeout(value = 120000, unit = TimeUnit.MILLISECONDS)
    public void testUpdateArguments() throws Exception {
        assumeTrue(OpenSsl.getLoadingFailureReason() == null);
        final OpenSsl cipher = OpenSsl
                .getInstance(AES.CTR_NO_PADDING);
        assertNotNull(cipher);

        cipher.init(OpenSsl.ENCRYPT_MODE, KEY, new IvParameterSpec(IV));

        // Require direct buffers
        ByteBuffer input = ByteBuffer.allocate(1024);
        ByteBuffer output = ByteBuffer.allocate(1024);

        final ByteBuffer finalInput = input;
        final ByteBuffer finalOutput = output;
        Exception ex = assertThrows(IllegalArgumentException.class, () -> cipher.update(finalInput, finalOutput));
        assertTrue(ex.getMessage().contains("Direct buffers are required"));

        // Output buffer length should be sufficient to store output data
        input = ByteBuffer.allocateDirect(1024);
        output = ByteBuffer.allocateDirect(1000);
        final ByteBuffer finalInput1 = input;
        final ByteBuffer finalOutput1 = output;
        ex = assertThrows(ShortBufferException.class, () -> cipher.update(finalInput1, finalOutput1));
        assertTrue(ex.getMessage().contains("Output buffer is not sufficient"));

    }

}
