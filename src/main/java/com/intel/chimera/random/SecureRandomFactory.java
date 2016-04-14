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
package com.intel.chimera.random;

import java.util.Properties;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.intel.chimera.utils.Utils;
import com.intel.chimera.utils.ReflectionUtils;

import static com.intel.chimera.conf.ConfigurationKeys
    .CHIMERA_CRYPTO_SECURE_RANDOM_CLASSES_KEY;

/**
 * This is the factory class used for {@link SecureRandom}.
 */
public class SecureRandomFactory {
  public final static Logger LOG = LoggerFactory
      .getLogger(SecureRandomFactory.class);

  private SecureRandomFactory() {}

  /**
   * Gets a SecureRandom instance for specified props.
   *
   * @param props the configuration properties.
   * @return SecureRandom the secureRandom object.Null value will be returned if no
   *         SecureRandom classes with props.
   */
  public static SecureRandom getSecureRandom(Properties props) {
    String secureRandomClasses = props.getProperty(
        CHIMERA_CRYPTO_SECURE_RANDOM_CLASSES_KEY);
    if (secureRandomClasses == null) {
      secureRandomClasses = System.getProperty(
          CHIMERA_CRYPTO_SECURE_RANDOM_CLASSES_KEY);
    }

    SecureRandom random = null;
    if (secureRandomClasses != null) {
      for (String klassName : Utils.splitClassNames(secureRandomClasses, ",")) {
        try {
          final Class<?> klass = ReflectionUtils.getClassByName(klassName);
          random = (SecureRandom) ReflectionUtils.newInstance(klass, props);
          if (random != null) {
            break;
          }
        } catch (ClassCastException e) {
          LOG.error("Class {} is not a Cipher.", klassName);
        } catch (ClassNotFoundException e) {
          LOG.error("Cipher {} not found.", klassName);
        }
      }
    }

    return (random == null) ? new JavaSecureRandom(props) : random;
  }
}
