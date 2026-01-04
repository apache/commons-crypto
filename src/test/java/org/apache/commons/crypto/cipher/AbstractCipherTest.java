 /*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.commons.crypto.cipher;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.fail;

import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.SecureRandom;
import java.util.Properties;
import java.util.Random;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.crypto.utils.AES;
import org.apache.commons.crypto.utils.ReflectionUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import jakarta.xml.bind.DatatypeConverter;

public abstract class AbstractCipherTest {

	public static final String OPENSSL_CIPHER_CLASSNAME = OpenSslCipher.class.getName();

	public static final String JCE_CIPHER_CLASSNAME = JceCipher.class.getName();

	// data
	public static final int BYTEBUFFER_SIZE = 1000;

	// cipher
	static final byte[] KEY = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x11, 0x12, 0x13, 0x14,
			0x15, 0x16, 0x17, 0x18, 0x19, 0x20, 0x21, 0x22, 0x23, 0x24 };
	static final byte[] IV = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
			0x08 };
	public String[] cipherTests;
	private Properties props;

	protected String cipherClass;
	protected String[] transformations = {
		AES.CBC_NO_PADDING,
		AES.CBC_PKCS5_PADDING,
		AES.CTR_NO_PADDING,
	}; // Note: GCM transform is currently only supported for OpenSSL (OpenSslGaloisCounterMode)

	private CryptoCipher enc, dec;

	/** Test byte array whose data is randomly generated */
	private void byteArrayTest(final String transformation, final byte[] key, final byte[] iv) throws Exception {
		final int blockSize = enc.getBlockSize();

		// AES_CBC_NOPADDING only accepts data whose size is the multiple of
		// block size
		final int[] dataLenList = transformation.equals(AES.CBC_NO_PADDING) ? new int[] { 10 * 1024 }
				: new int[] { 10 * 1024, 10 * 1024 - 3 };
		for (final int dataLen : dataLenList) {
			final byte[] plainText = new byte[dataLen];
			final Random random = new SecureRandom();
			random.nextBytes(plainText);
			final byte[] cipherText = new byte[dataLen + blockSize];

			// check update method with inputs whose sizes are the multiple of
			// block size or not
			final int[] bufferLenList = { 2 * 1024 - 128, 2 * 1024 - 125 };
			for (final int bufferLen : bufferLenList) {
				resetCipher(transformation, key, iv);

				int offset = 0;
				// encrypt (update + doFinal) the data
				int cipherPos = 0;
				for (int i = 0; i < dataLen / bufferLen; i++) {
					cipherPos += enc.update(plainText, offset, bufferLen, cipherText, cipherPos);
					offset += bufferLen;
				}
				cipherPos += enc.doFinal(plainText, offset, dataLen % bufferLen, cipherText, cipherPos);

				offset = 0;
				// decrypt (update + doFinal) the data
				final byte[] realPlainText = new byte[cipherPos + blockSize];
				int plainPos = 0;
				for (int i = 0; i < cipherPos / bufferLen; i++) {
					plainPos += dec.update(cipherText, offset, bufferLen, realPlainText, plainPos);
					offset += bufferLen;
				}
				plainPos += dec.doFinal(cipherText, offset, cipherPos % bufferLen, realPlainText, plainPos);

				// verify
				assertEquals(dataLen, plainPos, "random byte array length changes after transformation");

				final byte[] shrinkPlainText = new byte[plainPos];
				System.arraycopy(realPlainText, 0, shrinkPlainText, 0, plainPos);
				assertArrayEquals(plainText, shrinkPlainText, "random byte array contents changes after transformation");
			}
		}
	}

	/** Test byte array whose data is planned in {@link TestData} */
	private void byteArrayTest(final String transformation, final byte[] key, final byte[] iv, final byte[] input,
			final byte[] output) throws Exception {
		resetCipher(transformation, key, iv);
		final int blockSize = enc.getBlockSize();

		byte[] temp = new byte[input.length + blockSize];
		final int n = enc.doFinal(input, 0, input.length, temp, 0);
		final byte[] cipherText = new byte[n];
		System.arraycopy(temp, 0, cipherText, 0, n);
		assertArrayEquals(output, cipherText, "byte array encryption error.");

		temp = new byte[cipherText.length + blockSize];
		final int m = dec.doFinal(cipherText, 0, cipherText.length, temp, 0);
		final byte[] plainText = new byte[m];
		System.arraycopy(temp, 0, plainText, 0, m);
		assertArrayEquals(input, plainText, "byte array decryption error.");
	}

	private void byteBufferTest(final String transformation, final byte[] key, final byte[] iv, final ByteBuffer input,
			final ByteBuffer output) throws Exception {
		final ByteBuffer decResult = ByteBuffer.allocateDirect(BYTEBUFFER_SIZE);
		final ByteBuffer encResult = ByteBuffer.allocateDirect(BYTEBUFFER_SIZE);

		try (final CryptoCipher enc = getCipher(transformation); final CryptoCipher dec = getCipher(transformation)) {

			enc.init(Cipher.ENCRYPT_MODE, AES.newSecretKeySpec(key), new IvParameterSpec(iv));
			dec.init(Cipher.DECRYPT_MODE, AES.newSecretKeySpec(key), new IvParameterSpec(iv));

			//
			// encryption pass
			//
			enc.doFinal(input, encResult);
			input.flip();
			encResult.flip();
			if (!output.equals(encResult)) {
				final byte[] b = new byte[output.remaining()];
				output.get(b);
				final byte[] c = new byte[encResult.remaining()];
				encResult.get(c);
				fail("AES failed encryption - expected " + DatatypeConverter.printHexBinary(b)
						+ " got " + DatatypeConverter.printHexBinary(c));
			}

			//
			// decryption pass
			//
			dec.doFinal(encResult, decResult);
			decResult.flip();

			if (!input.equals(decResult)) {
				final byte[] inArray = new byte[input.remaining()];
				final byte[] decResultArray = new byte[decResult.remaining()];
				input.get(inArray);
				decResult.get(decResultArray);
				fail();
			}
		}
	}

	private CryptoCipher getCipher(final String transformation) throws ClassNotFoundException {
		return (CryptoCipher) ReflectionUtils.newInstance(ReflectionUtils.getClassByName(cipherClass), props,
				transformation);
	}

    protected abstract void init();

	SecretKeySpec newSecretKeySpec() {
        return AES.newSecretKeySpec(KEY);
    }

	private void resetCipher(final String transformation, final byte[] key, final byte[] iv)
			throws ClassNotFoundException, InvalidKeyException, InvalidAlgorithmParameterException {
		enc = getCipher(transformation);
		dec = getCipher(transformation);

		enc.init(Cipher.ENCRYPT_MODE, AES.newSecretKeySpec(key), new IvParameterSpec(iv));

		dec.init(Cipher.DECRYPT_MODE, AES.newSecretKeySpec(key), new IvParameterSpec(iv));
	}

	@BeforeEach
	public void setup() {
		init();
		assertNotNull(cipherClass, "cipherClass");
		assertNotNull(transformations, "transformations");
		props = new Properties();
		props.setProperty(CryptoCipherFactory.CLASSES_KEY, cipherClass);
	}

	@Test
	void testCloseTestAfterInit() throws Exception {
		// This test deliberately does not use try with resources in order to control
		// the sequence of operations exactly
        try (final CryptoCipher enc = getCipher(transformations[0])) {
            enc.init(Cipher.ENCRYPT_MODE, newSecretKeySpec(), new IvParameterSpec(IV));
        }
	}

	@Test
	void testCloseTestNoInit() throws Exception {
		// This test deliberately does not use try with resources in order to control
		// the sequence of operations exactly
		try (final CryptoCipher enc = getCipher(transformations[0])) {
		    // empty
		}
	}

	@Test
	void testCloseTestRepeat() throws Exception {
		// This test deliberately does not use try with resources in order to control
		// the sequence of operations exactly
        try (final CryptoCipher enc = getCipher(transformations[0])) {
            enc.close();
            enc.close(); // repeat the close
        }
	}

  /** Uses the small data set in {@link TestData}. */
	@Test
	void testCryptoTest() throws Exception {
		for (final String tran : transformations) {
			cipherTests = TestData.getTestData(tran);
			assertNotNull(cipherTests, "TestData cannot supply data for: " + tran);
			for (int i = 0; i != cipherTests.length; i += 5) {
				final byte[] key = DatatypeConverter.parseHexBinary(cipherTests[i + 1]);
				final byte[] iv = DatatypeConverter.parseHexBinary(cipherTests[i + 2]);

				final byte[] inputBytes = DatatypeConverter.parseHexBinary(cipherTests[i + 3]);
				final byte[] outputBytes = DatatypeConverter.parseHexBinary(cipherTests[i + 4]);

				final ByteBuffer inputBuffer = ByteBuffer.allocateDirect(inputBytes.length);
				final ByteBuffer outputBuffer = ByteBuffer.allocateDirect(outputBytes.length);
				inputBuffer.put(inputBytes);
				inputBuffer.flip();
				outputBuffer.put(outputBytes);
				outputBuffer.flip();

				byteBufferTest(tran, key, iv, inputBuffer, outputBuffer);
				byteArrayTest(tran, key, iv, inputBytes, outputBytes);
			}

			/** Uses randomly generated big data set */
			byteArrayTest(tran, KEY, IV);
		}
	}

	@Test
	void testInvalidIV() throws Exception {
		for (final String transform : transformations) {
			try (final CryptoCipher cipher = getCipher(transform)) {
				assertNotNull(cipher);
				final byte[] invalidIV = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
						0x0d, 0x0e, 0x0f, 0x11 };
				assertThrows(InvalidAlgorithmParameterException.class, () -> cipher.init(OpenSsl.ENCRYPT_MODE, newSecretKeySpec(), new IvParameterSpec(invalidIV)));
			}
		}
	}

	@Test
	void testInvalidIVClass() throws Exception {
		for (final String transform : transformations) {
			try (final CryptoCipher cipher = getCipher(transform)) {
				assertNotNull(cipher);
				assertThrows(InvalidAlgorithmParameterException.class, () -> cipher.init(OpenSsl.ENCRYPT_MODE, newSecretKeySpec(), new GCMParameterSpec(IV.length, IV)));
			}
		}
	}

	@Test
	void testInvalidKey() throws Exception {
		for (final String transform : transformations) {
			try (final CryptoCipher cipher = getCipher(transform)) {
				assertNotNull(cipher);

				final byte[] invalidKey = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
						0x0c, 0x0d, 0x0e, 0x0f, 0x11 };
				assertThrows(InvalidKeyException.class, () -> cipher.init(OpenSsl.ENCRYPT_MODE, AES.newSecretKeySpec(invalidKey), new IvParameterSpec(IV)));
			}
		}
	}

	@Test
	void testInvalidTransform() {
		assertThrows(IllegalArgumentException.class,
				() -> getCipher("AES/CBR/NoPadding/garbage/garbage").close());
	}

	@Test
	void testNullTransform() {
		assertThrows(IllegalArgumentException.class,
				() -> getCipher(null).close());
	}

	@Test
    void testReInitAfterClose() throws Exception {
        // This test deliberately does not use try with resources in order to control
        // the sequence of operations exactly
        try (final CryptoCipher enc = getCipher(transformations[0])) {
            enc.init(Cipher.ENCRYPT_MODE, newSecretKeySpec(), new IvParameterSpec(IV));
            enc.close();
            enc.init(Cipher.DECRYPT_MODE, newSecretKeySpec(), new IvParameterSpec(IV));
        }
    }

	@Test
	void testReInitTest() throws Exception {
		// This test deliberately does not use try with resources in order to control
		// the sequence of operations exactly
        try (final CryptoCipher enc = getCipher(transformations[0])) {
            enc.init(Cipher.ENCRYPT_MODE, newSecretKeySpec(), new IvParameterSpec(IV));
            enc.init(Cipher.DECRYPT_MODE, newSecretKeySpec(), new IvParameterSpec(IV));
            enc.init(Cipher.ENCRYPT_MODE, newSecretKeySpec(), new IvParameterSpec(IV));
        }
	}
}
