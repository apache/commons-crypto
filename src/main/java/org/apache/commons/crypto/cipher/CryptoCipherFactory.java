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

import org.apache.commons.crypto.conf.ConfigurationKeys;
import org.apache.commons.crypto.utils.ReflectionUtils;
import org.apache.commons.crypto.utils.Utils;

/**
 * This is the factory class used for creating cipher class
 */
public class CryptoCipherFactory {

    /**
     * The default value for crypto cipher.
     */
    private static final String CIPHER_CLASSES_DEFAULT = 
            OpensslCipher.class.getName();

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
    public static CryptoCipher getInstance(String transformation,
            Properties props) throws GeneralSecurityException {

        CryptoCipher cipher = null;

        StringBuilder errorMessage = new StringBuilder("CryptoCipher ");
        for (String klass : Utils.splitClassNames(getCipherClassString(props), ",")) {
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

        if (cipher != null) {
            return cipher;
        } else if (Utils.isFallbackEnabled(props)) {
            return new JceCipher(props,transformation);
        } else {
            errorMessage.append(" is not available or transformation " +
                    transformation + " is not supported.");
            throw new GeneralSecurityException(errorMessage.toString());
        }
    }

    /**
     * Gets a cipher for algorithm/mode/padding in config value
     * commons.crypto.cipher.transformation
     *
     * @param transformation the name of the transformation, e.g.,
     * <i>AES/CBC/PKCS5Padding</i>.
     * See the Java Cryptography Architecture Standard Algorithm Name Documentation
     * for information about standard transformation names.
     * @return CryptoCipher the cipher object Null value will be returned if no
     *         cipher classes with transformation configured.
     * @throws GeneralSecurityException if JCE cipher initialize failed
     */
    public static CryptoCipher getInstance(String transformation)
            throws GeneralSecurityException {
        return getInstance(transformation, new Properties());
    }

    /**
     * Gets the cipher class.
     *
     * @param props The <code>Properties</code> class represents a set of
     *        properties.
     * @return the cipher class based on the props.
     */
    private static String getCipherClassString(Properties props) {
        final String configName = ConfigurationKeys.CIPHER_CLASSES_KEY;
        String cipherClassString = props.getProperty(configName) != null ? props
                .getProperty(configName, CIPHER_CLASSES_DEFAULT)
                : System.getProperty(configName,
                CIPHER_CLASSES_DEFAULT);
        if (cipherClassString.isEmpty()) {
            cipherClassString = CIPHER_CLASSES_DEFAULT;
        }
        return cipherClassString;
    }

}
