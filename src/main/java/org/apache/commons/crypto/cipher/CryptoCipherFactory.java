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
import java.util.Properties;

import org.apache.commons.crypto.conf.ConfigurationKeys;
import org.apache.commons.crypto.utils.ReflectionUtils;
import org.apache.commons.crypto.utils.Utils;

/**
 * This is the factory class used for creating cipher class
 */
public class CryptoCipherFactory {

    /**
     * Defines the internal CryptoCipher implementations.
     * <p>
     * Usage:
     * <p>
     * <code>
     * props.setProperty(CIPHER_CLASSES_KEY, CipherProvider.OPENSSL.getClassName());
     * props.setProperty(...); // if required by the implementation
     * cipher = CryptoCipherFactory.getInstance(transformation, props);
     * </code>
     */
    public enum CipherProvider {

        /**
         * The OpenSSL cipher implementation (using JNI)
         * <p>
         * This implementation does not use any properties
         */
        OPENSSL(OpensslCipher.class),
        
        /**
         * The JCE cipher implementation from the JVM
         * <p>
         * uses {@link ConfigurationKeys#CIPHER_JCE_PROVIDER_KEY}) as the provider name.
         * This is optional
         */
        JCE(JceCipher.class);

        private final Class<? extends CryptoCipher> klass;

        private final String className;

        /**
         * Constructs a CihpherProvider.
         *
         * @param klass the implementation of provider
         */
        private CipherProvider(Class<? extends CryptoCipher> klass) {
            this.klass = klass;
            this.className = klass.getName();
        }

        /**
         * Gets the class name of the provider.
         *
         * @return the name of the provider class
         */
        public String getClassName() {
            return className;
        }

        /**
         * Gets the implementation class of the provider.
         *
         * @return the implementation class of the provider
         */
        public Class<? extends CryptoCipher> getImplClass() {
            return klass;
        }
    }

    /**
     * The default value (OpensslCipher) for crypto cipher.
     */
    private static final String CIPHER_CLASSES_DEFAULT = CipherProvider
            .OPENSSL.getClassName().concat(",").concat(CipherProvider.JCE
            .getClassName());

    /**
     * The private Constructor of {@link CryptoCipherFactory}.
     */
    private CryptoCipherFactory() {
    }

    /**
     * Gets a cipher instance for specified algorithm/mode/padding.
     *
     * @param props  the configuration properties (uses ConfigurationKeys.CIPHER_CLASSES_KEY)
     * @param transformation  algorithm/mode/padding
     * @return CryptoCipher  the cipher  (defaults to OpensslCipher)
     * @throws GeneralSecurityException if cipher initialize failed
     * @throws IllegalArgumentException if no classname(s)
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
        }
        if (errorMessage.length() == 0) {
            throw new IllegalArgumentException("No classname(s) provided");
        }
        errorMessage.append(" is not available or transformation " +
                transformation + " is not supported.");
        throw new GeneralSecurityException(errorMessage.toString());
    }

    /**
     * Gets a cipher for algorithm/mode/padding in config value
     * commons.crypto.cipher.transformation
     *
     * @param transformation the name of the transformation, e.g.,
     * <i>AES/CBC/PKCS5Padding</i>.
     * See the Java Cryptography Architecture Standard Algorithm Name Documentation
     * for information about standard transformation names.
     * @return CryptoCipher the cipher object (defaults to OpensslCipher if available, else JceCipher)
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
        String cipherClassString = props.getProperty(ConfigurationKeys.CIPHER_CLASSES_KEY, CIPHER_CLASSES_DEFAULT);
        if (cipherClassString.isEmpty()) { // TODO does it make sense to treat the empty string as the default?
            cipherClassString = CIPHER_CLASSES_DEFAULT;
        }
        return cipherClassString;
    }

}
