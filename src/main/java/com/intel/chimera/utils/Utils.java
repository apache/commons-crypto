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
package com.intel.chimera.utils;

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.Properties;

import com.intel.chimera.cipher.Cipher;
import com.intel.chimera.cipher.CipherFactory;
import com.intel.chimera.cipher.CipherTransformation;

import static com.intel.chimera.conf.ConfigurationKeys.CHIMERA_CRYPTO_STREAM_BUFFER_SIZE_DEFAULT;
import static com.intel.chimera.conf.ConfigurationKeys.CHIMERA_CRYPTO_STREAM_BUFFER_SIZE_KEY;
import static com.intel.chimera.conf.ConfigurationKeys.CHIMERA_CRYPTO_CIPHER_CLASSES_DEFAULT;
import static com.intel.chimera.conf.ConfigurationKeys.CHIMERA_CRYPTO_CIPHER_CLASSES_KEY;
import static com.intel.chimera.conf.ConfigurationKeys.CHIMERA_CRYPTO_CIPHER_JCE_PROVIDER_KEY;
import static com.intel.chimera.conf.ConfigurationKeys.CHIMERA_CRYPTO_LIB_NAME_KEY;
import static com.intel.chimera.conf.ConfigurationKeys.CHIMERA_CRYPTO_LIB_PATH_KEY;
import static com.intel.chimera.conf.ConfigurationKeys.CHIMERA_CRYPTO_SECURE_RANDOM_DEVICE_FILE_PATH_DEFAULT;
import static com.intel.chimera.conf.ConfigurationKeys.CHIMERA_CRYPTO_SECURE_RANDOM_DEVICE_FILE_PATH_KEY;
import static com.intel.chimera.conf.ConfigurationKeys.CHIMERA_SYSTEM_PROPERTIES_FILE;
import static com.intel.chimera.conf.ConfigurationKeys.CHIMERA_CRYPTO_LIB_TEMPDIR_KEY;

public class Utils {
  private static final int MIN_BUFFER_SIZE = 512;

  protected static final CipherTransformation AES_CTR_NOPADDING = CipherTransformation.AES_CTR_NOPADDING;

  /**
   * For AES, the algorithm block is fixed size of 128 bits.
   * @see http://en.wikipedia.org/wiki/Advanced_Encryption_Standard
   */
  private static final int AES_BLOCK_SIZE = AES_CTR_NOPADDING.getAlgorithmBlockSize();

  static {
    loadChimeraSystemProperties();
  }

  /**
   * load system properties when configuration file of the name
   * {@link #CHIMERA_SYSTEM_PROPERTIES_FILE} is found
   */
  private static void loadChimeraSystemProperties() {
    try {
      InputStream is = Thread.currentThread().getContextClassLoader()
          .getResourceAsStream(CHIMERA_SYSTEM_PROPERTIES_FILE);

      if (is == null)
        return; // no configuration file is found

      // Load property file
      Properties props = new Properties();
      props.load(is);
      is.close();
      Enumeration<?> names = props.propertyNames();
      while (names.hasMoreElements()) {
        String name = (String) names.nextElement();
        if (name.startsWith("chimera.")) {
          if (System.getProperty(name) == null) {
            System.setProperty(name, props.getProperty(name));
          }
        }
      }
    } catch (Throwable ex) {
      System.err.println("Could not load '"
          + CHIMERA_SYSTEM_PROPERTIES_FILE + "' from classpath: "
          + ex.toString());
    }
  }

  /** Forcibly free the direct buffer. */
  public static void freeDirectBuffer(ByteBuffer buffer) {
    if (buffer instanceof sun.nio.ch.DirectBuffer) {
      final sun.misc.Cleaner bufferCleaner =
          ((sun.nio.ch.DirectBuffer) buffer).cleaner();
      bufferCleaner.clean();
    }
  }

  /** Read crypto buffer size */
  public static int getBufferSize(Properties props) {
    String bufferSizeStr = props.getProperty(
        CHIMERA_CRYPTO_STREAM_BUFFER_SIZE_KEY);
    if (bufferSizeStr == null || bufferSizeStr.isEmpty()) {
      bufferSizeStr = System
        .getProperty(CHIMERA_CRYPTO_STREAM_BUFFER_SIZE_KEY);
    }
    if (bufferSizeStr == null || bufferSizeStr.isEmpty()) {
      return CHIMERA_CRYPTO_STREAM_BUFFER_SIZE_DEFAULT;
    } else {
      return Integer.parseInt(bufferSizeStr);
    }
  }

  public static String getCipherClassString(Properties props) {
    final String configName = CHIMERA_CRYPTO_CIPHER_CLASSES_KEY;
    return props.getProperty(configName) != null ? props.getProperty(configName) : System
        .getProperty(configName, CHIMERA_CRYPTO_CIPHER_CLASSES_DEFAULT);
  }

  public static String getJCEProvider(Properties props) {
    return props.getProperty(CHIMERA_CRYPTO_CIPHER_JCE_PROVIDER_KEY) != null ?
        props.getProperty(CHIMERA_CRYPTO_CIPHER_JCE_PROVIDER_KEY) :
        System.getProperty(CHIMERA_CRYPTO_CIPHER_JCE_PROVIDER_KEY);
  }

  public static String getRandomDevPath(Properties props) {
    String devPath = props.getProperty(
        CHIMERA_CRYPTO_SECURE_RANDOM_DEVICE_FILE_PATH_KEY);
    if (devPath == null) {
      devPath = System.getProperty(
          CHIMERA_CRYPTO_SECURE_RANDOM_DEVICE_FILE_PATH_KEY,
          CHIMERA_CRYPTO_SECURE_RANDOM_DEVICE_FILE_PATH_DEFAULT);
    }
    return devPath;
  }

  public static String getLibPath() {
    return System.getProperty(CHIMERA_CRYPTO_LIB_PATH_KEY);
  }

  public static String getLibName() {
    return System.getProperty(CHIMERA_CRYPTO_LIB_NAME_KEY);
  }

  public static String getTmpDir() {
    return System.getProperty(CHIMERA_CRYPTO_LIB_TEMPDIR_KEY,
        System.getProperty("java.io.tmpdir"));
  }

  /** AES/CTR/NoPadding is required */
  public static void checkStreamCipher(Cipher cipher) throws IOException {
    if (cipher.getTransformation() != CipherTransformation.AES_CTR_NOPADDING) {
      throw new IOException("AES/CTR/NoPadding is required");
    }
  }

  /** Check and floor buffer size */
  public static int checkBufferSize(Cipher cipher, int bufferSize) {
    checkArgument(bufferSize >= MIN_BUFFER_SIZE,
        "Minimum value of buffer size is " + MIN_BUFFER_SIZE + ".");
    return bufferSize - bufferSize % cipher.getTransformation()
        .getAlgorithmBlockSize();
  }

  /**
   * This method is only for Counter (CTR) mode. Generally the Cipher calculates the IV and maintain encryption context internally.
   * For example a {@link javax.crypto.Cipher} will maintain its encryption
   * context internally when we do encryption/decryption using the
   * Cipher#update interface.
   * <p/>
   * Encryption/Decryption is not always on the entire file. For example,
   * in Hadoop, a node may only decrypt a portion of a file (i.e. a split).
   * In these situations, the counter is derived from the file position.
   * <p/>
   * The IV can be calculated by combining the initial IV and the counter with
   * a lossless operation (concatenation, addition, or XOR).
   * @see http://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Counter_.28CTR.29
   *
   * @param initIV initial IV
   * @param counter counter for input stream position
   * @param IV the IV for input stream position
   */
  public static void calculateIV(byte[] initIV, long counter, byte[] IV) {
    checkArgument(initIV.length == AES_BLOCK_SIZE);
    checkArgument(IV.length == AES_BLOCK_SIZE);

    int i = IV.length; // IV length
    int j = 0; // counter bytes index
    int sum = 0;
    while (i-- > 0) {
      // (sum >>> Byte.SIZE) is the carry for addition
      sum = (initIV[i] & 0xff) + (sum >>> Byte.SIZE);
      if (j++ < 8) { // Big-endian, and long is 8 bytes length
        sum += (byte) counter & 0xff;
        counter >>>= 8;
      }
      IV[i] = (byte) sum;
    }
  }

  /**
   * Helper method to create a Cipher instance and throws only IOException
   */
  public static Cipher getCipherInstance(CipherTransformation transformation,
      Properties props) throws IOException {
    try {
      return CipherFactory.getInstance(transformation, props);
    } catch (GeneralSecurityException e) {
      throw new IOException(e);
    }
  }

  /**
   * Ensures the truth of an expression involving one or more parameters to
   * the calling method.
   *
   * @param expression a boolean expression
   * @throws IllegalArgumentException if expression is false
   */
  public static void checkArgument(boolean expression) {
    if(!expression) {
      throw new IllegalArgumentException();
    }
  }

  /**
   * @param expression   a boolean expression
   * @param errorMessage the exception message to use if the check fails;
   *                     will be converted to a string using <code>String
   *                     .valueOf(Object)</code>
   * @throws IllegalArgumentException if expression is false
   */
  public static void checkArgument(boolean expression, Object errorMessage) {
    if (!expression) {
      throw new IllegalArgumentException(String.valueOf(errorMessage));
    }
  }

  /**
   * Ensures that an object reference passed as a parameter to the calling
   * method is not null.
   *
   * @param reference an object reference
   * @return the non-null reference that was validated
   * @throws NullPointerException if reference is null
   */
  public static <T> T checkNotNull(T reference) {
    if(reference == null) {
      throw new NullPointerException();
    } else {
      return reference;
    }
  }

  /**
   * Ensures the truth of an expression involving the state of the calling
   * instance, but not involving any parameters to the calling method.
   *
   * @param expression a boolean expression
   * @throws IllegalStateException if expression is false
   */
  public static void checkState(boolean expression) {
    if(!expression) {
      throw new IllegalStateException();
    }
  }

  /**
   * Split class names sequence into substrings, Trim each substring into an
   * entry,and returns an list of the entries.
   *
   * @param clazzNames a string consist of a list of the entries joined by a
   *                   delimiter
   * @param separator  a delimiter for the input string
   * @return a list of entries
   */
  public static List<String> splitClassNames(String clazzNames,
      String separator) {
    List<String> res = new ArrayList<String>();
    if (clazzNames == null || clazzNames.isEmpty()) {
      return res;
    }

    for (String clazzName : clazzNames.split(separator)) {
      clazzName = clazzName.trim();
      if (!clazzName.isEmpty()) {
        res.add(clazzName);
      }
    }
    return res;
  }
}
