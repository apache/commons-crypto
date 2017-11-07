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

package org.apache.commons.crypto.cipher;

import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;

import org.junit.Assert;
import org.junit.Assume;
import org.junit.Test;

public class OpenSslCipherTest extends AbstractCipherTest {

    @Override
    public void init() {
        Assume.assumeTrue(OpenSsl.getLoadingFailureReason() == null);
        transformations = new String[] {
                "AES/CBC/NoPadding",
                "AES/CBC/PKCS5Padding",
                "AES/CTR/NoPadding"};
        cipherClass = OPENSSL_CIPHER_CLASSNAME;
    }

    @Test(expected = NoSuchAlgorithmException.class, timeout = 120000)
    public void testInvalidAlgorithm() throws Exception {
        Assume.assumeTrue(OpenSsl.getLoadingFailureReason() == null);

        try {
            OpenSsl.getInstance("AES2/CTR/NoPadding");
            Assert.fail("Should specify correct algorithm.");
        } catch (NoSuchAlgorithmException e) {
            Assert.assertTrue(e.getMessage().contains(
                    "Doesn't support algorithm: AES2 and mode: CTR"));
            throw e;
        }
    }

    @Test(expected = NoSuchPaddingException.class, timeout = 120000)
    public void testInvalidPadding() throws Exception {
        Assume.assumeTrue(OpenSsl.getLoadingFailureReason() == null);

        try {
            OpenSsl.getInstance("AES/CTR/NoPadding2");
            Assert.fail("Should specify correct padding.");
        } catch (NoSuchPaddingException e) {
            Assert.assertTrue(e.getMessage().contains(
                    "Doesn't support padding: NoPadding2"));
            throw e;
        }
    }

    @Test(expected = NoSuchAlgorithmException.class, timeout = 120000)
    public void testInvalidMode() throws Exception {
        Assume.assumeTrue(OpenSsl.getLoadingFailureReason() == null);
        try {
            OpenSsl.getInstance("AES/CTR2/NoPadding");
            Assert.fail("java.security.NoSuchAlgorithmException should be thrown.");
        } catch (NoSuchAlgorithmException e) {
            Assert.assertTrue(e.getMessage().contains(
                    "Doesn't support algorithm: AES and mode: CTR2"));
            throw e;
        }
    }

    @Test(timeout = 120000)
    public void testUpdateArguments() throws Exception {
        Assume.assumeTrue(OpenSsl.getLoadingFailureReason() == null);
        OpenSsl cipher = OpenSsl
                .getInstance("AES/CTR/NoPadding");
        Assert.assertNotNull(cipher);

        cipher.init(OpenSsl.ENCRYPT_MODE, KEY, new IvParameterSpec(IV));

        // Require direct buffers
        ByteBuffer input = ByteBuffer.allocate(1024);
        ByteBuffer output = ByteBuffer.allocate(1024);

        try {
            cipher.update(input, output);
            Assert.fail("Input and output buffer should be direct buffer.");
        } catch (IllegalArgumentException e) {
            Assert.assertTrue(e.getMessage().contains(
                    "Direct buffers are required"));
        }

        // Output buffer length should be sufficient to store output data
        input = ByteBuffer.allocateDirect(1024);
        output = ByteBuffer.allocateDirect(1000);
        try {
            cipher.update(input, output);
            Assert.fail("Output buffer length should be sufficient "
                    + "to store output data");
        } catch (ShortBufferException e) {
            Assert.assertTrue(e.getMessage().contains(
                    "Output buffer is not sufficient"));
        }
    }

    @Test(timeout = 120000)
    public void testDoFinalArguments() throws Exception {
        Assume.assumeTrue(OpenSsl.getLoadingFailureReason() == null);
        OpenSsl cipher = OpenSsl
                .getInstance("AES/CTR/NoPadding");
        Assert.assertNotNull(cipher);

        cipher.init(OpenSsl.ENCRYPT_MODE, KEY, new IvParameterSpec(IV));

        // Require direct buffer
        ByteBuffer input = ByteBuffer.allocate(1024);
        ByteBuffer output = ByteBuffer.allocate(1024);

        try {
            cipher.doFinal(input, output);
            Assert.fail("Output buffer should be direct buffer.");
        } catch (IllegalArgumentException e) {
            Assert.assertTrue(e.getMessage().contains(
                    "Direct buffer is required"));
        }
    }

    @Test(expected = InvalidKeyException.class, timeout = 120000)
    public void testInvalidKey() throws Exception {
        Assume.assumeTrue(OpenSsl.getLoadingFailureReason() == null);
        OpenSsl cipher = OpenSsl
                .getInstance("AES/CTR/NoPadding");
        Assert.assertNotNull(cipher);

        final byte[] invalidKey = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
                0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x11 };
        try {
            cipher.init(OpenSsl.ENCRYPT_MODE, invalidKey, new IvParameterSpec(IV));
            Assert.fail("java.security.InvalidKeyException should be thrown.");
        } catch (Exception e) {
            Assert.assertTrue(e.getMessage().contains("Invalid AES key length: " + invalidKey.length + " bytes"));
            throw e;
        }
    }

    @Test(expected = InvalidAlgorithmParameterException.class, timeout = 120000)
    public void testInvalidIV() throws Exception {
        Assume.assumeTrue(OpenSsl.getLoadingFailureReason() == null);
        OpenSsl cipher = OpenSsl
                .getInstance("AES/CTR/NoPadding");
        Assert.assertNotNull(cipher);

        final byte[] invalidIV = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
                0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x11 };
        try {
            cipher.init(OpenSsl.ENCRYPT_MODE, KEY, new IvParameterSpec(invalidIV));
            Assert.fail("java.security.InvalidAlgorithmParameterException should be thrown.");
        } catch (Exception e) {
            Assert.assertTrue(e.getMessage().contains("Wrong IV length: must be 16 bytes long"));
            throw e;
        }
    }

}
