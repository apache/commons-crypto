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
package com.intel.chimera.cipher;

import com.intel.chimera.utils.ReflectionUtils;
import com.intel.chimera.utils.Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

/**
 * This is the factory class used for creating cipher class
 */
public class CipherFactory {
  public final static Logger LOG = LoggerFactory.getLogger(CipherFactory.class);

  /**
   * Get a cipher instance for specified algorithm/mode/padding.
   *
   * @param props
   *          the configuration properties
   * @param transformation
   *          algorithm/mode/padding
   * @return Cipher the cipher. Null value will be returned if no
   *         cipher classes with transformation configured.
   */
  public static Cipher getInstance(CipherTransformation transformation,
      Properties props) throws GeneralSecurityException {
    List<Class<? extends Cipher>> klasses = getCipherClasses(props);
    Cipher cipher = null;
    if (klasses != null) {
      for (Class<? extends Cipher> klass : klasses) {
        try {
          cipher = ReflectionUtils.newInstance(klass, props, transformation);
          if (cipher != null) {
            LOG.debug("Using cipher {} for transformation {}.", klass.getName(),
                transformation.getName());
            break;
          }
        } catch (Exception e) {
          LOG.error("Cipher {} is not available or transformation {} is not " +
            "supported.", klass.getName(), transformation.getName());
        }
      }
    }

    return (cipher == null) ? new JceCipher(props, transformation) : cipher;
  }

  /**
   * Get a cipher for algorithm/mode/padding in config value
   * chimera.crypto.cipher.transformation
   *
   * @return Cipher the cipher object Null value will be returned if no
   *         cipher classes with transformation configured.
   */
  public static Cipher getInstance(CipherTransformation transformation)
      throws GeneralSecurityException {
    return getInstance(transformation, null);
  }

  private static List<Class<? extends Cipher>> getCipherClasses(Properties props) {
    List<Class<? extends Cipher>> result = new ArrayList<Class<? extends
        Cipher>>();
    String cipherClassString = Utils.getCipherClassString(props);
    if (cipherClassString == null) {
      LOG.debug("No cipher classes configured.");
      return null;
    }
    for (String c : Utils.splitClassNames(cipherClassString, ",")) {
      try {
        Class<?> cls = ReflectionUtils.getClassByName(c);
        result.add(cls.asSubclass(Cipher.class));
      } catch (ClassCastException e) {
        LOG.error("Class {} is not a Cipher.", c);
      } catch (ClassNotFoundException e) {
        LOG.error("Cipher {} not found.", c);
      }
    }

    return result;
  }

}
