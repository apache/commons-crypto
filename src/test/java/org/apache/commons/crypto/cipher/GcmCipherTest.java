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
import java.security.Key;
import java.util.Arrays;
import java.util.Properties;
import java.util.Random;

import org.apache.commons.crypto.utils.Utils;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

public class GcmCipherTest {

    Properties props = null;
    String cipherClass = null;
    String transformation = "AES/GCM/NoPadding";

    private String[] kHex;
    private String[] pHex;
    private String[] ivHex;
    private String[] aadHex;
    private String[] cHex;
    private String[] tHex;

    @Before
    public void setup() {
        //init
        cipherClass = OpenSslCipher.class.getName();

        props = new Properties();
        props.setProperty(CryptoCipherFactory.CLASSES_KEY,
                cipherClass);
        initTestData();
    }

    /**
     * NIST AES Test Vectors
     * http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-spec.pdf
     */
    @Test
    public void testGcmNistCase2() {
        // key length:          16 bytes
        // plain text length:   16 bytes
        // iv length:           12 bytes
        // aad length:          0 bytes

        String kHex = "00000000000000000000000000000000";
        String pHex = "00000000000000000000000000000000";
        String ivHex = "000000000000000000000000";
        String aadHex = "";

        String cHex = "0388dace60b6a392f328c2b971b2fe78";
        String tHex = "ab6e47d42cec13bdf53a67b21257bddf";

        testGcmEncryption(kHex, pHex, ivHex, aadHex, cHex, tHex);
        testGcmDecryption(kHex, pHex, ivHex, aadHex, cHex, tHex);
        testGcmByteBuffer(kHex, pHex, ivHex, aadHex, cHex, tHex);
        testGcmReturnDataAfterTagVerified(kHex, pHex, ivHex, aadHex, cHex, tHex);
        testGcmArbitraryLengthUpdate(kHex, pHex, ivHex, aadHex, cHex, tHex);
    }

    @Test
    public void testGcmNistCase4() {
        // key length:          16 bytes
        // plain text length:   60 bytes
        // iv length:           12 bytes
        // aad length:          20 bytes

        String kHex = "feffe9928665731c6d6a8f9467308308";
        String pHex = "d9313225f88406e5a55909c5aff5269a"
                + "86a7a9531534f7da2e4c303d8a318a72"
                + "1c3c0c95956809532fcf0e2449a6b525"
                + "b16aedf5aa0de657ba637b39";
        String ivHex = "cafebabefacedbaddecaf888";
        String aadHex = "feedfacedeadbeeffeedfacedeadbeef"
                + "abaddad2";

        String cHex = "42831ec2217774244b7221b784d0d49c"
                + "e3aa212f2c02a4e035c17e2329aca12e"
                + "21d514b25466931c7d8f6a5aac84aa05"
                + "1ba30b396a0aac973d58e091";
        String tHex = "5bc94fbc3221a5db94fae95ae7121a47";

        testGcmEncryption(kHex, pHex, ivHex, aadHex, cHex, tHex);
        testGcmDecryption(kHex, pHex, ivHex, aadHex, cHex, tHex);
        testGcmByteBuffer(kHex, pHex, ivHex, aadHex, cHex, tHex);
        testGcmReturnDataAfterTagVerified(kHex, pHex, ivHex, aadHex, cHex, tHex);
        testGcmArbitraryLengthUpdate(kHex, pHex, ivHex, aadHex, cHex, tHex);
    }

    @Test
    public void testGcmNistCase5(){
        // key length:          16 bytes
        // plain text length:   60 bytes
        // iv length:           8 bytes
        // aad length:          20 bytes

        String kHex = "feffe9928665731c6d6a8f9467308308";

        String pHex = "d9313225f88406e5a55909c5aff5269a"
                + "86a7a9531534f7da2e4c303d8a318a72"
                + "1c3c0c95956809532fcf0e2449a6b525"
                + "b16aedf5aa0de657ba637b39";

        String ivHex ="cafebabefacedbad"; // 64bits < 96bits

        String aadHex="feedfacedeadbeeffeedfacedeadbeef"
                + "abaddad2";

        String cHex = "61353b4c2806934a777ff51fa22a4755"
                + "699b2a714fcdc6f83766e5f97b6c7423"
                + "73806900e49f24b22b097544d4896b42"
                + "4989b5e1ebac0f07c23f4598";

        String tHex = "3612d2e79e3b0785561be14aaca2fccb";

        testGcmEncryption(kHex, pHex, ivHex, aadHex, cHex, tHex);
        testGcmDecryption(kHex, pHex, ivHex, aadHex, cHex, tHex);
        testGcmByteBuffer(kHex, pHex, ivHex, aadHex, cHex, tHex);
        testGcmReturnDataAfterTagVerified(kHex, pHex, ivHex, aadHex, cHex, tHex);
        testGcmArbitraryLengthUpdate(kHex, pHex, ivHex, aadHex, cHex, tHex);
    }

    @Test
    public void testGcmNistCase6(){
        // key length:          16 bytes
        // plain text length:   60 bytes
        // iv length:           60 bytes
        // aad length:          20 bytes

        String kHex = "feffe9928665731c6d6a8f9467308308";

        String pHex = "d9313225f88406e5a55909c5aff5269a"
                + "86a7a9531534f7da2e4c303d8a318a72"
                + "1c3c0c95956809532fcf0e2449a6b525"
                + "b16aedf5aa0de657ba637b39";

        String ivHex ="9313225df88406e555909c5aff5269aa"
                + "6a7a9538534f7da1e4c303d2a318a728"
                + "c3c0c95156809539fcf0e2429a6b5254"
                + "16aedbf5a0de6a57a637b39b"; // > 96bits

        String aadHex="feedfacedeadbeeffeedfacedeadbeef"
                + "abaddad2";

        String cHex = "8ce24998625615b603a033aca13fb894"
                + "be9112a5c3a211a8ba262a3cca7e2ca7"
                + "01e4a9a4fba43c90ccdcb281d48c7c6f"
                + "d62875d2aca417034c34aee5";

        String tHex = "619cc5aefffe0bfa462af43c1699d050";

        testGcmEncryption(kHex, pHex, ivHex, aadHex, cHex, tHex);
        testGcmDecryption(kHex, pHex, ivHex, aadHex, cHex, tHex);
        testGcmByteBuffer(kHex, pHex, ivHex, aadHex, cHex, tHex);
        testGcmReturnDataAfterTagVerified(kHex, pHex, ivHex, aadHex, cHex, tHex);
        testGcmArbitraryLengthUpdate(kHex, pHex, ivHex, aadHex, cHex, tHex);
    }

    @Test
    public void testGcmNistCases(){
        for(int i = 0; i < kHex.length; i++) {
            testGcmEncryption(kHex[i], pHex[i], ivHex[i], aadHex[i], cHex[i], tHex[i]);
            testGcmDecryption(kHex[i], pHex[i], ivHex[i], aadHex[i], cHex[i], tHex[i]);
            testGcmByteBuffer(kHex[i], pHex[i], ivHex[i], aadHex[i], cHex[i], tHex[i]);
            testGcmReturnDataAfterTagVerified(kHex[i], pHex[i], ivHex[i], aadHex[i], cHex[i], tHex[i]);
            testGcmArbitraryLengthUpdate(kHex[i], pHex[i], ivHex[i], aadHex[i], cHex[i], tHex[i]);
        }
    }

    @Test(expected = AEADBadTagException.class)
    public void testGcmTamperedData() throws Exception {

        Random r = new Random();
        int textLength = r.nextInt(1024*1024);
        int ivLength = r.nextInt(60);
        int keyLength = 16;
        int tagLength = 128;  // bits
        int aadLength = r.nextInt(128);

        byte[] keyBytes = new byte[keyLength];
        byte[] plainBytes = new byte[textLength];
        byte[] ivBytes = new byte[ivLength];
        byte[] aadBytes = new byte[aadLength];

        r.nextBytes(keyBytes);
        r.nextBytes(plainBytes);
        r.nextBytes(ivBytes);
        r.nextBytes(aadBytes);

        byte[] encOutput = new byte[plainBytes.length + (tagLength >> 3)];
        byte[] decOutput = new byte[plainBytes.length];

        try {
            CryptoCipher c = Utils.getCipherInstance(transformation, props);
            Key key = new SecretKeySpec(keyBytes, "AES");

            GCMParameterSpec iv = new GCMParameterSpec(tagLength, ivBytes);
            c.init(Cipher.ENCRYPT_MODE, key, iv);
            c.updateAAD(aadBytes);
            c.doFinal(plainBytes, 0, plainBytes.length, encOutput, 0);
            c.close();
        }
        catch (Exception ex) {
            Assert.fail(ex.getMessage());
        }

        // Tamper the encrypted data.
        encOutput[0] = (byte)(encOutput[0] + 1);

        try {
            CryptoCipher c = Utils.getCipherInstance(transformation, props);
            Key key = new SecretKeySpec(keyBytes, "AES");

            GCMParameterSpec iv = new GCMParameterSpec(tagLength, ivBytes);
            c.init(Cipher.DECRYPT_MODE, key, iv);
            c.updateAAD(aadBytes);
            c.doFinal(encOutput, 0, encOutput.length, decOutput, 0);
            c.close();
        }
        catch (AEADBadTagException ex) {
            Assert.assertTrue("Tag mismatch!".equals(ex.getMessage()));
            throw ex;
        }
    }

    @Test
    public void testGMac() {
        // for GMAC,  aad is the input data,
        // tag is the digest message

        Random r = new Random();
        byte[] keyBytes = new byte[32];
        byte[] input = new byte[0];  // no input for GMAC
        byte[] ivBytes = new byte[16];

        byte[] tag_orig = new byte[16]; // JDK's tag
        byte[] tag = new byte[16];

        // aad is the data to be hashed
        byte[] aad = new byte[r.nextInt() % 1000 + 1000 ];

        r.nextBytes(keyBytes);
        r.nextBytes(input);
        r.nextBytes(ivBytes);
        r.nextBytes(aad);

        try {
            {
                Cipher c = Cipher.getInstance(transformation);
                Key key = new SecretKeySpec(keyBytes, "AES");
                GCMParameterSpec iv = new GCMParameterSpec(128, ivBytes);
                c.init(Cipher.ENCRYPT_MODE, key, iv);
                c.updateAAD(aad);
                c.doFinal(input, 0, input.length, tag_orig, 0);
            }

            {
                CryptoCipher c = Utils.getCipherInstance(transformation, props);
                Key key = new SecretKeySpec(keyBytes, "AES");
                GCMParameterSpec iv = new GCMParameterSpec(128, ivBytes);
                c.init(Cipher.ENCRYPT_MODE, key, iv);
                c.updateAAD(aad);
                c.doFinal(input, 0, input.length, tag, 0);
                c.close();
            }

            // tag should be the same as JDK's cipher
            Assert.assertArrayEquals(tag_orig, tag);

            // like JDK's decrypt mode. The plaintext+tag is the input for decrypt mode
            // let's verify the add & tag now
            {
                CryptoCipher c = Utils.getCipherInstance(transformation, props);
                Key key = new SecretKeySpec(keyBytes, "AES");
                GCMParameterSpec iv = new GCMParameterSpec(128, ivBytes);
                c.init(Cipher.DECRYPT_MODE, key, iv);
                c.updateAAD(aad);
                c.doFinal(tag, 0, tag.length, input, 0);
                c.close();
            }
        }
        catch (Exception ex) {
            Assert.fail(ex.getMessage());
        }
    }

    @Test(expected = AEADBadTagException.class)
    public void testGMacTamperedData() throws Exception {
        Random r = new Random();
        byte[] keyBytes = new byte[32];
        byte[] input = new byte[0];
        byte[] ivBytes = new byte[16];

        byte[] tag = new byte[16];

        byte[] aad = new byte[r.nextInt() % 1000 + 1000 ];

        r.nextBytes(keyBytes);
        r.nextBytes(input);
        r.nextBytes(ivBytes);
        r.nextBytes(aad);

        try {
            CryptoCipher c = Utils.getCipherInstance(transformation, props);
            Key key = new SecretKeySpec(keyBytes, "AES");
            GCMParameterSpec iv = new GCMParameterSpec(128, ivBytes);
            c.init(Cipher.ENCRYPT_MODE, key, iv);
            c.updateAAD(aad);
            c.doFinal(input, 0, input.length, tag, 0);
            c.close();
        }
        catch (Exception ex) {
            Assert.fail(ex.getMessage());
        }

        try {
            // like JDK's decrypt mode. The plaintext+tag is the input for decrypt mode
            CryptoCipher c = Utils.getCipherInstance(transformation, props);
            Key key = new SecretKeySpec(keyBytes, "AES");
            GCMParameterSpec iv = new GCMParameterSpec(128, ivBytes);
            c.init(Cipher.DECRYPT_MODE, key, iv);

            // if the origin data is tampered
            aad[0] = (byte) (aad[0] + 1);
            c.updateAAD(aad);

            c.doFinal(tag, 0, tag.length, input, 0);
            c.close();

        }
        catch (AEADBadTagException ex) {
            Assert.assertTrue("Tag mismatch!".equals(ex.getMessage()));
            throw ex;
        }
        catch (Exception ex) {
            Assert.fail(ex.getMessage());
        }
    }

    private void testGcmEncryption(String kHex, String pHex, String ivHex, String aadHex,
                                   String cHex, String tHex){

        byte[] keyBytes = DatatypeConverter.parseHexBinary(kHex);
        byte[] input = DatatypeConverter.parseHexBinary(pHex);
        byte[] ivBytes = DatatypeConverter.parseHexBinary(ivHex);
        byte[] aad = DatatypeConverter.parseHexBinary(aadHex);
        byte[] expectedOutput = DatatypeConverter.parseHexBinary(cHex+tHex);

        byte[] output = new byte[expectedOutput.length];

        try {
            CryptoCipher c = Utils.getCipherInstance(transformation, props);

            Key key = new SecretKeySpec(keyBytes, "AES");

            GCMParameterSpec iv = new GCMParameterSpec(128, ivBytes);
            c.init(Cipher.ENCRYPT_MODE, key, iv);
            c.updateAAD(aad);

            c.doFinal(input, 0, input.length, output, 0);

            Assert.assertArrayEquals(expectedOutput, output);
            c.close();
        }
        catch (Exception ex) {
            Assert.fail(ex.getMessage());
        }
    }

    private void testGcmArbitraryLengthUpdate(String kHex, String pHex, String ivHex, String aadHex,
                                              String cHex, String tHex){

        byte[] keyBytes = DatatypeConverter.parseHexBinary(kHex);
        byte[] input = DatatypeConverter.parseHexBinary(pHex);
        byte[] ivBytes = DatatypeConverter.parseHexBinary(ivHex);
        byte[] aad = DatatypeConverter.parseHexBinary(aadHex);
        byte[] expectedOutput = DatatypeConverter.parseHexBinary(cHex+tHex);

        byte[] encOutput = new byte[expectedOutput.length];
        byte[] decOutput = new byte[input.length];

        try {
            Random r = new Random();

            CryptoCipher enc = Utils.getCipherInstance(transformation, props);
            Key key = new SecretKeySpec(keyBytes, "AES");
            GCMParameterSpec iv = new GCMParameterSpec(128, ivBytes);
            enc.init(Cipher.ENCRYPT_MODE, key, iv);
            if (aad.length > 0) {
                int len1 = r.nextInt(aad.length) ;
                byte[] aad1 = Arrays.copyOfRange(aad, 0, len1);
                byte[] aad2 = Arrays.copyOfRange(aad, len1, aad.length);
                enc.updateAAD(aad1);
                enc.updateAAD(aad2);
            }

            int partLen = r.nextInt(input.length);
            int len = enc.update(input, 0, partLen, encOutput, 0);
            Assert.assertTrue(len == partLen);
            len = enc.doFinal(input, partLen, input.length - partLen, encOutput, partLen);
            Assert.assertTrue(len == (input.length + (iv.getTLen() >> 3) - partLen));

            Assert.assertArrayEquals(expectedOutput, encOutput);
            enc.close();

            // Decryption
            CryptoCipher dec = Utils.getCipherInstance(transformation, props);
            dec.init(Cipher.DECRYPT_MODE, new SecretKeySpec(keyBytes, "AES"),
                    new GCMParameterSpec(128, ivBytes));
            if (aad.length > 0) {
                int len1 = r.nextInt(aad.length) ;
                byte[] aad1 = Arrays.copyOfRange(aad, 0, len1);
                byte[] aad2 = Arrays.copyOfRange(aad, len1, aad.length);
                dec.updateAAD(aad1);
                dec.updateAAD(aad2);
            }
            byte[] decInput = encOutput;
            partLen = r.nextInt(input.length);
            len = dec.update(decInput, 0, partLen, decOutput, 0);
            Assert.assertTrue(len == 0);
            len = dec.doFinal(decInput, partLen, decInput.length - partLen, decOutput, 0);
            Assert.assertTrue(len == input.length);

            Assert.assertArrayEquals(input, decOutput);
            dec.close();
        }
        catch (Exception ex) {
            Assert.fail(ex.getMessage());
        }
    }

    private void testGcmDecryption(String kHex, String pHex, String ivHex, String aadHex,
                                   String cHex, String tHex){

        byte[] keyBytes = DatatypeConverter.parseHexBinary(kHex);
        byte[] plainBytes = DatatypeConverter.parseHexBinary(pHex);
        byte[] ivBytes = DatatypeConverter.parseHexBinary(ivHex);

        byte[] aad = DatatypeConverter.parseHexBinary(aadHex);
        byte[] cipherBytes = DatatypeConverter.parseHexBinary(cHex+tHex);

        byte[] input = cipherBytes;
        byte[] output = new byte[plainBytes.length];

        try {
            CryptoCipher c = Utils.getCipherInstance(transformation, props);

            Key key = new SecretKeySpec(keyBytes, "AES");

            GCMParameterSpec iv = new GCMParameterSpec(128, ivBytes);
            c.init(Cipher.DECRYPT_MODE, key, iv);
            c.updateAAD(aad);
            c.doFinal(input, 0, input.length, output, 0);

            Assert.assertArrayEquals(plainBytes, output);
            c.close();
        }
        catch (Exception ex) {
            Assert.fail(ex.getMessage());
        }
    }

    private void testGcmReturnDataAfterTagVerified(String kHex, String pHex, String ivHex, String aadHex,
                                                   String cHex, String tHex){

        byte[] keyBytes = DatatypeConverter.parseHexBinary(kHex);
        byte[] plainBytes = DatatypeConverter.parseHexBinary(pHex);
        byte[] ivBytes = DatatypeConverter.parseHexBinary(ivHex);

        byte[] aad = DatatypeConverter.parseHexBinary(aadHex);
        byte[] cipherBytes = DatatypeConverter.parseHexBinary(cHex+tHex);

        byte[] input = cipherBytes;
        byte[] output = new byte[plainBytes.length];

        try {
            CryptoCipher c = Utils.getCipherInstance(transformation, props);

            Key key = new SecretKeySpec(keyBytes, "AES");

            GCMParameterSpec iv = new GCMParameterSpec(128, ivBytes);
            c.init(Cipher.DECRYPT_MODE, key, iv);
            c.updateAAD(aad);

            //only return recovered data after tag is successfully verified
            int len = c.update(input, 0, input.length, output, 0);
            Assert.assertTrue(len == 0);
            len += c.doFinal(input, input.length, 0, output, 0);
            Assert.assertTrue(len == plainBytes.length);

            Assert.assertArrayEquals(plainBytes, output);
            c.close();
        }
        catch (Exception ex) {
            Assert.fail(ex.getMessage());
        }
    }

    private void testGcmByteBuffer(String kHex, String pHex, String ivHex, String aadHex,
                                   String cHex, String tHex){

        byte[] keyBytes = DatatypeConverter.parseHexBinary(kHex);
        byte[] plainText = DatatypeConverter.parseHexBinary(pHex);
        byte[] ivBytes = DatatypeConverter.parseHexBinary(ivHex);
        byte[] aad = DatatypeConverter.parseHexBinary(aadHex);
        byte[] cipherText = DatatypeConverter.parseHexBinary(cHex+tHex);

        byte[] encOutput = new byte[cipherText.length];
        byte[] decOutput = new byte[plainText.length];

        try {

            ByteBuffer bfAAD = ByteBuffer.allocateDirect(aad.length);
            bfAAD.put(aad);

            ByteBuffer bfPlainText;
            ByteBuffer bfCipherText;
            bfPlainText = ByteBuffer.allocateDirect(plainText.length);
            bfCipherText = ByteBuffer.allocateDirect(encOutput.length);

            // Encryption -------------------
            CryptoCipher c = Utils.getCipherInstance(transformation, props);
            Key key = new SecretKeySpec(keyBytes, "AES");
            GCMParameterSpec iv = new GCMParameterSpec(128, ivBytes);
            c.init(Cipher.ENCRYPT_MODE, key, iv);

            bfAAD.flip();
            c.updateAAD(bfAAD);

            bfPlainText.put(plainText);
            bfPlainText.flip();
            bfCipherText.position(0);

            c.doFinal(bfPlainText, bfCipherText);

            bfCipherText.flip();
            bfCipherText.get(encOutput);
            Assert.assertArrayEquals(cipherText, encOutput);
            c.close();

            // Decryption -------------------
            CryptoCipher dec = Utils.getCipherInstance(transformation, props);
            dec.init(Cipher.DECRYPT_MODE, new SecretKeySpec(keyBytes, "AES"),
                    new GCMParameterSpec(128, ivBytes));
            bfAAD.flip();
            dec.updateAAD(bfAAD);
            bfCipherText.clear();
            bfPlainText.clear();
            bfCipherText.put(cipherText);
            bfCipherText.flip();
            dec.doFinal(bfCipherText, bfPlainText);
            bfPlainText.flip();
            bfPlainText.get(decOutput);
            Assert.assertArrayEquals(plainText, decOutput);
            dec.close();
        }
        catch (Exception ex) {
            Assert.fail(ex.getMessage());
        }
    }

    private void initTestData() {

        int casesNumber = 4;

        kHex = new String[casesNumber];
        pHex = new String[casesNumber];
        ivHex = new String[casesNumber];
        aadHex = new String[casesNumber];
        cHex = new String[casesNumber];
        tHex = new String[casesNumber];

        // http://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf
        // http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-spec.pdf
        // NIST Case2  -----------------------------
        // key length:          16 bytes
        // plain text length:   16 bytes
        // iv length:           12 bytes
        // aad length:          0 bytes
        kHex[0] = "00000000000000000000000000000000";
        pHex[0] = "00000000000000000000000000000000";
        ivHex[0]  = "000000000000000000000000";
        aadHex[0]  = "";
        cHex[0]  = "0388dace60b6a392f328c2b971b2fe78";
        tHex[0]  = "ab6e47d42cec13bdf53a67b21257bddf";

        // NIST Case4 ---------------------------------
        // key length:          16 bytes
        // plain text length:   60 bytes
        // iv length:           12 bytes
        // aad length:          20 bytes
        kHex[1] = "feffe9928665731c6d6a8f9467308308";
        pHex[1] = "d9313225f88406e5a55909c5aff5269a"
                + "86a7a9531534f7da2e4c303d8a318a72"
                + "1c3c0c95956809532fcf0e2449a6b525"
                + "b16aedf5aa0de657ba637b39";
        ivHex[1] = "cafebabefacedbaddecaf888";
        aadHex[1] = "feedfacedeadbeeffeedfacedeadbeef"
                + "abaddad2";
        cHex[1] = "42831ec2217774244b7221b784d0d49c"
                + "e3aa212f2c02a4e035c17e2329aca12e"
                + "21d514b25466931c7d8f6a5aac84aa05"
                + "1ba30b396a0aac973d58e091";
        tHex[1] = "5bc94fbc3221a5db94fae95ae7121a47";

        // NIST Case5 ---------------------------------
        // key length:          16 bytes
        // plain text length:   60 bytes
        // iv length:           8 bytes
        // aad length:          20 bytes
        kHex[2] = "feffe9928665731c6d6a8f9467308308";
        pHex[2] = "d9313225f88406e5a55909c5aff5269a"
                + "86a7a9531534f7da2e4c303d8a318a72"
                + "1c3c0c95956809532fcf0e2449a6b525"
                + "b16aedf5aa0de657ba637b39";
        ivHex[2] ="cafebabefacedbad"; // 64bits < 96bits
        aadHex[2]="feedfacedeadbeeffeedfacedeadbeef"
                + "abaddad2";
        cHex[2] = "61353b4c2806934a777ff51fa22a4755"
                + "699b2a714fcdc6f83766e5f97b6c7423"
                + "73806900e49f24b22b097544d4896b42"
                + "4989b5e1ebac0f07c23f4598";
        tHex[2] = "3612d2e79e3b0785561be14aaca2fccb";

        // NIST Case6 ---------------------------------
        // key length:          16 bytes
        // plain text length:   60 bytes
        // iv length:           60 bytes
        // aad length:          20 bytes
        kHex[3] = "feffe9928665731c6d6a8f9467308308";
        pHex[3] = "d9313225f88406e5a55909c5aff5269a"
                + "86a7a9531534f7da2e4c303d8a318a72"
                + "1c3c0c95956809532fcf0e2449a6b525"
                + "b16aedf5aa0de657ba637b39";
        ivHex[3] = "9313225df88406e555909c5aff5269aa"
                + "6a7a9538534f7da1e4c303d2a318a728"
                + "c3c0c95156809539fcf0e2429a6b5254"
                + "16aedbf5a0de6a57a637b39b"; // > 96bits
        aadHex[3] = "feedfacedeadbeeffeedfacedeadbeef"
                + "abaddad2";
        cHex[3] = "8ce24998625615b603a033aca13fb894"
                + "be9112a5c3a211a8ba262a3cca7e2ca7"
                + "01e4a9a4fba43c90ccdcb281d48c7c6f"
                + "d62875d2aca417034c34aee5";
        tHex[3] = "619cc5aefffe0bfa462af43c1699d050";
    }
}
