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

import java.security.GeneralSecurityException;
import java.util.List;
import java.util.Properties;

import org.apache.commons.crypto.utils.ReflectionUtils;
import org.apache.commons.crypto.utils.Utils;

/**
 * This is the factory class used for creating cipher class
 */
public class CryptoCipherFactory {

    /**
     * The private Constructor of {@link CryptoCipherFactory}.
     */
    private CryptoCipherFactory() {
    }

    /**
     * Gets a cipher instance for specified algorithm/mode/padding.
     *
     * @param props the configuration properties
     * @param transformation algorithm/mode/padding
     * @return CryptoCipher the cipher. Null value will be returned if no cipher
     *         classes with transformation configured.
     * @throws GeneralSecurityException if cipher initialize failed
     */
    public static CryptoCipher getInstance(CipherTransformation transformation,
            Properties props) throws GeneralSecurityException {

        List<String> klasses =  Utils.splitClassNames(
                Utils.getCipherClassString(props), ",");
        CryptoCipher cipher = null;

        StringBuilder errorMessage = new StringBuilder("CryptoCipher ");
        if (klasses != null) {
            for (String klass : klasses) {
                try {
                    Class<?> cls = ReflectionUtils.getClassByName(klass);
                    cipher = ReflectionUtils.newInstance(cls.asSubclass
                            (CryptoCipher.class), props, transformation);
                    if (cipher != null) {
                        break;
                    }
                } catch (Exception e) {
                    errorMessage.append("{" + klass + "}");
                }
            }
        }

        if (cipher != null) {
            return cipher;
        } else if (Utils.isFallbackEnable(props)) {
            return new JceCipher(props,transformation);
        } else {
            errorMessage.append(" is not available or transformation " +
                    transformation.getName() + " is not supported.");
            throw new GeneralSecurityException(errorMessage.toString());
        }
    }

    /**
     * Gets a cipher for algorithm/mode/padding in config value
     * commons.crypto.cipher.transformation
     *
     * @param transformation CipherTransformation instance.
     * @return CryptoCipher the cipher object Null value will be returned if no
     *         cipher classes with transformation configured.
     * @throws GeneralSecurityException if JCE cipher initialize failed
     */
    public static CryptoCipher getInstance(CipherTransformation transformation)
            throws GeneralSecurityException {
        return getInstance(transformation, new Properties());
    }

}
