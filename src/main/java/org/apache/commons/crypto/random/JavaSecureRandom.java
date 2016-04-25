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
package org.apache.commons.crypto.random;

import java.security.NoSuchAlgorithmException;
import java.util.Properties;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.apache.commons.crypto.conf.ConfigurationKeys;

/**
 * A SecureRandom of Java implementation.
 */
public class JavaSecureRandom implements SecureRandom {
  private static final Log LOG =
      LogFactory.getLog(JavaSecureRandom.class.getName());

  private java.security.SecureRandom instance;

  /**
   * Constructs a {@link org.apache.commons.crypto.random.JavaSecureRandom}.
   *
   * @param properties the configuration properties.
   */
  public JavaSecureRandom(Properties properties) {
    try {
      instance = java.security.SecureRandom
          .getInstance(properties.getProperty(
              ConfigurationKeys.COMMONS_CRYPTO_SECURE_RANDOM_JAVA_ALGORITHM_KEY,
              ConfigurationKeys.COMMONS_CRYPTO_SECURE_RANDOM_JAVA_ALGORITHM_DEFAULT));
    } catch (NoSuchAlgorithmException e) {
      LOG.error("Failed to create java secure random due to error: " + e);
    }
  }

  /**
   * Overrides {@link java.lang.AutoCloseable#close()}.
   * For{@link JavaSecureRandom}, we don't need to recycle resource.
   */
  @Override
  public void close() {
    // do nothing
  }

  /**
   * Overrides {@link org.apache.commons.crypto.random.SecureRandom#nextBytes(byte[])}.
   * Generates random bytes and places them into a user-supplied byte array.
   * The number of random bytes produced is equal to the length of the byte array.
   *
   * @param bytes the array to be filled in with random bytes.
   */
  @Override
  public void nextBytes(byte[] bytes) {
    instance.nextBytes(bytes);
  }
}
