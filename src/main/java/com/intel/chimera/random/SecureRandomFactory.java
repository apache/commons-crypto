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

import com.intel.chimera.utils.ReflectionUtils;
import static com.intel.chimera.ConfigurationKeys.CHIMERA_SECURE_RANDOM_IMPL_KEY;

/**
 * The Factory for SecureRandom.
 */
public class SecureRandomFactory {

  public static SecureRandom getSecureRandom(Properties props) {
    String secureRandomImpl = props.getProperty(CHIMERA_SECURE_RANDOM_IMPL_KEY);
    if (secureRandomImpl == null) {
      secureRandomImpl = System.getProperty(CHIMERA_SECURE_RANDOM_IMPL_KEY);
    }
    final Class<? extends SecureRandom> klass = ReflectionUtils
        .getClass(secureRandomImpl, OsSecureRandom.class, SecureRandom.class);

    SecureRandom random;
    try {
      random = ReflectionUtils.newInstance(klass, props);
    } catch (Exception e) {
      random = new JavaSecureRandom();
    }

    return random;
  }
}
