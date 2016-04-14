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
package com.intel.chimera.conf;

import com.intel.chimera.cipher.JceCipher;

/**
 * The ConfigurationKeys contains Configuration keys and default values.
 */
public class ConfigurationKeys {

  /**
   * The prefix named with project name.
   */
  public static final String CHIMERA_PREFIX = "chimera.";

  /**
   * The filename of configuration file.
   */
  public static final String CHIMERA_SYSTEM_PROPERTIES_FILE =
      CHIMERA_PREFIX + "properties";

  /**
   * The prefix of crypto configuration.
   */
  public static final String CONF_PREFIX =
      CHIMERA_PREFIX + "crypto.";

  /**
   * The configuration key of implementation class for crypto cipher.
   * The values of CHIMERA_CRYPTO_CIPHER_CLASSES_KEY can be
   * "com.intel.chimera.cipher.JceCipher" and "com.intel.chimera.cipher.OpensslCipher".
   * And it takes a common separated list.
   * The "com.intel.chimera.cipher.JceCipher" use jce provider to
   * implement {@link com.intel.chimera.cipher.Cipher} and
   * the "com.intel.chimera.cipher.OpensslCipher" use jni into openssl to implement.
   * Note that for each value,the first value which can be created without exception
   * will be used (priority by order).
    */
  public static final String CHIMERA_CRYPTO_CIPHER_CLASSES_KEY =
      CONF_PREFIX + "cipher.classes";

  /**
   * The default value for crypto cipher.
   */
  public static final String CHIMERA_CRYPTO_CIPHER_CLASSES_DEFAULT =
      JceCipher.class.getName();

  /**
   * The configuration key of the provider class for JCE cipher.
   */
  public static final String CHIMERA_CRYPTO_CIPHER_JCE_PROVIDER_KEY =
      CONF_PREFIX + "cipher.jce.provider";

  // security random related configuration keys
  /**
   * The configuration key of the file path for secure random device.
   */
  public static final String CHIMERA_CRYPTO_SECURE_RANDOM_DEVICE_FILE_PATH_KEY =
      CONF_PREFIX + "secure.random.device.file.path";

  /**
   * The default value of the file path for secure random device.
   */
  public static final String CHIMERA_CRYPTO_SECURE_RANDOM_DEVICE_FILE_PATH_DEFAULT =
      "/dev/urandom";

  /**
   * The configuration key of the algorithm of secure random.
   */
  public static final String CHIMERA_CRYPTO_SECURE_RANDOM_JAVA_ALGORITHM_KEY =
      CONF_PREFIX + "secure.random.java.algorithm";

  /**
   * The default value of the algorithm of secure random.
   */
  public static final String
      CHIMERA_CRYPTO_SECURE_RANDOM_JAVA_ALGORITHM_DEFAULT = "SHA1PRNG";

  /**
   * The configuration key of the implementation class for secure random.
   * The values of CHIMERA_CRYPTO_SECURE_RANDOM_CLASSES_KEY can be
   * "com.intel.chimera.random.JavaSecureRandom" and "com.intel.chimera.random.OpensslSecureRandom".
   * And it takes a common separated list.
   * The "com.intel.chimera.random.JavaSecureRandom" use java to
   * implement {@link com.intel.chimera.random.SecureRandom} and
   * the "com.intel.chimera.random.OpensslSecureRandom" use jni into openssl to implement.
   * Note that for each value,the first value which can be created without exception
   * will be used (priority by order).
   */
  public static final String CHIMERA_CRYPTO_SECURE_RANDOM_CLASSES_KEY =
      CONF_PREFIX + "secure.random.classes";

  /**
   * The configuration key of the buffer size for stream.
   */
  public static final String CHIMERA_CRYPTO_STREAM_BUFFER_SIZE_KEY =
      CONF_PREFIX + "stream.buffer.size";

  // stream related configuration keys
  /**
   * The default value of the buffer size for stream.
   */
  public static final int CHIMERA_CRYPTO_STREAM_BUFFER_SIZE_DEFAULT = 8192;

  // native lib related configuration keys
  /**
   * The configuration key of the path for loading crypto library.
   */
  public static final String CHIMERA_CRYPTO_LIB_PATH_KEY =
      CONF_PREFIX + "lib.path";

  /**
   * The configuration key of the file name for loading crypto library.
   */
  public static final String CHIMERA_CRYPTO_LIB_NAME_KEY =
      CONF_PREFIX + "lib.name";

  /**
   * The configuration key of temp directory for extracting crypto library.
   */
  public static final String CHIMERA_CRYPTO_LIB_TEMPDIR_KEY =
      CONF_PREFIX + "lib.tempdir";

  private ConfigurationKeys() {}
}
