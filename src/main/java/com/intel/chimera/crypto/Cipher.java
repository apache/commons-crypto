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
package com.intel.chimera.crypto;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.util.List;
import java.util.Properties;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.base.Splitter;
import com.google.common.collect.Lists;
import com.intel.chimera.utils.Utils;
import com.intel.chimera.utils.ReflectionUtils;

/**
 * Abstract Cipher class
 */
public abstract class Cipher {
  public final static Logger LOG = LoggerFactory.getLogger(Cipher.class);

  public static final int ENCRYPT_MODE = 1;
  public static final int DECRYPT_MODE = 0;
  
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
  public static Cipher getInstance(Properties props,
      CipherTransformation transformation) throws GeneralSecurityException  {
    List<Class<? extends Cipher>> klasses =
        getCipherClasses(props, transformation);
    Cipher cipher = null;
    if (klasses != null) {
      for (Class<? extends Cipher> klass : klasses) {
        try {
        	cipher = ReflectionUtils.newInstance(klass, props, transformation);
        	if(cipher != null) {
        		LOG.debug("Using cipher {} for transformation {}.", klass.getName(), transformation.getName());
        		break;
        	}
        } catch (Exception e) {
          LOG.debug("Cipher {} is not available or transformation {} is not supported.",
              klass.getName(), transformation.getName());
        }
      }
    }
    
    return (cipher == null)?new JceCipher(props, transformation):cipher;
  }

  /**
   * Get a cipher for algorithm/mode/padding in config value
   * chimera.crypto.cipher.transformation
   * 
   * @return Cipher the cipher object Null value will be returned if no
   *         cipher classes with transformation configured.
   */
  public static Cipher getInstance() throws GeneralSecurityException {
    return getInstance(new Properties());
  }

  /**
   * Get a cipher for algorithm/mode/padding in config value
   * chimera.crypto.cipher.transformation
   *
   * @param props the properties which contain the configurations
   *         of the crypto cipher
   * @return Cipher the cipher object Null value will be returned if no
   *         cipher classes with transformation configured.
   */
  public static Cipher getInstance(Properties props)
  		throws GeneralSecurityException {
    return getInstance(props, Utils.getCripherTransformation(props));
  }

  private static List<Class<? extends Cipher>> getCipherClasses(
      Properties props, CipherTransformation transformation) {
    List<Class<? extends Cipher>> result = Lists.newArrayList();
    String cipherClassString = Utils.getCipherClassString(props, transformation);
    if (cipherClassString == null) {
      LOG.debug("No cipher classes with cipher transformation configured.");
      return null;
    }
    for (String c : Splitter.on(',').trimResults().omitEmptyStrings().
        split(cipherClassString)) {
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
  
  /**
   * @return the CipherTransformation for this cipher.
   */
  public abstract CipherTransformation getTransformation();

  public abstract void init(int mode, byte[] key, byte[] iv) 
  		throws IOException;
  
  public abstract int update(ByteBuffer inBuffer, ByteBuffer outBuffer) 
      throws IOException;
  
  public abstract int doFinal(ByteBuffer inBuffer, ByteBuffer outBuffer) 
	      throws IOException;
  
  /**
   * Generate a number of secure, random bytes suitable for cryptographic use.
   * This method needs to be thread-safe.
   *
   * @param bytes byte array to populate with random data
   */
  public abstract void generateSecureRandom(byte[] bytes);
}
