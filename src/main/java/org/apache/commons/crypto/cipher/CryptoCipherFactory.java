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

import org.apache.commons.crypto.Crypto;
import org.apache.commons.crypto.utils.ReflectionUtils;
import org.apache.commons.crypto.utils.Utils;

/**
 * This is the factory class used for creating {@link CryptoCipher} instances.
 */
public class CryptoCipherFactory {

    /**
     * The configuration key of the provider class for JCE cipher.
     */
    public static final String JCE_PROVIDER_KEY = Crypto.CONF_PREFIX
            + "cipher.jce.provider";
    /**
     * The configuration key of the CryptoCipher implementation class.
     * <p>
     * The value of CLASSES_KEY needs to be the full name of a
     * class that implements the
     * {@link org.apache.commons.crypto.cipher.CryptoCipher CryptoCipher} interface
     * The internal classes are listed in the enum
     * {@link CipherProvider CipherProvider}
     * which can be used to obtain the full class name.
     * <p>
     * The value can also be a comma-separated list of class names in
     * order of descending priority.
     */

    public static final String CLASSES_KEY = Crypto.CONF_PREFIX
            + "cipher.classes";

    /**
     * Defines the internal CryptoCipher implementations.
     * <p>
     * Usage:
     * <blockquote><pre>
     * props.setProperty(CryptoCipherFactory.CLASSES_KEY, CipherProvider.OPENSSL.getClassName());
     * props.setProperty(...); // if required by the implementation
     * cipher = CryptoCipherFactory.getInstance(transformation, props);
     * </pre></blockquote>
     */
    public enum CipherProvider {

        /**
         * The OpenSSL cipher implementation (using JNI)
         * <p>
         * This implementation does not use any properties
         */
        // Please ensure the property description agrees with the implementation
        OPENSSL(OpenSslCipher.class),

        /**
         * The JCE cipher implementation from the JVM
         * <p>
         * uses the property {@link #JCE_PROVIDER_KEY}
         * to define the provider name, if present.
         */
        // Please ensure the property description agrees with the implementation
        JCE(JceCipher.class);

        private final Class<? extends CryptoCipher> klass;

        private final String className;

        /**
         * The private constructor.
         * @param klass the Class of CryptoCipher
         */
        private CipherProvider(final Class<? extends CryptoCipher> klass) {
            this.klass = klass;
            this.className = klass.getName();
        }

        /**
         * Gets the class name of the provider.
         *
         * @return the fully qualified name of the provider class
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
     * For AES, the algorithm block is fixed size of 128 bits.
     *
     * @see <a href="http://en.wikipedia.org/wiki/Advanced_Encryption_Standard">
     *      http://en.wikipedia.org/wiki/Advanced_Encryption_Standard</a>
     */
    public static final int AES_BLOCK_SIZE = 16;

    /**
     * The default value (OPENSSL,JCE) for crypto cipher.
     */
    private static final String CLASSES_DEFAULT =
            CipherProvider.OPENSSL.getClassName()
            .concat(",")
            .concat(CipherProvider.JCE.getClassName());
    /**
     * The private Constructor of {@link CryptoCipherFactory}.
     */
    private CryptoCipherFactory() {
    }

    /**
     * Gets a cipher instance for specified algorithm/mode/padding.
     *
     * @param props  the configuration properties - uses {@link #CLASSES_KEY}
     * @param transformation  algorithm/mode/padding
     * @return CryptoCipher  the cipher  (defaults to OpenSslCipher)
     * @throws GeneralSecurityException if cipher initialize failed
     * @throws IllegalArgumentException if no classname(s) were provided
     */
    public static CryptoCipher getCryptoCipher(final String transformation,
                                           final Properties props) throws GeneralSecurityException {

        final List<String> names = Utils.splitClassNames(getCipherClassString(props), ",");
        if (names.size() == 0) {
            throw new IllegalArgumentException("No classname(s) provided");
        }
        CryptoCipher cipher = null;
        Exception lastException = null;

        final StringBuilder errorMessage = new StringBuilder("CryptoCipher ");
        for (final String klass : names) {
            try {
                final Class<?> cls = ReflectionUtils.getClassByName(klass);
                cipher = ReflectionUtils.newInstance(cls.asSubclass
                        (CryptoCipher.class), props, transformation);
                if (cipher != null) {
                    break;
                }
            } catch (final Exception e) {
                lastException = e;
                errorMessage.append("{" + klass + "}");
            }
        }

        if (cipher != null) {
            return cipher;
        }
        errorMessage.append(" is not available or transformation " +
                transformation + " is not supported.");
        throw new GeneralSecurityException(errorMessage.toString(), lastException);
    }

    /**
     * Gets a cipher for algorithm/mode/padding in config value
     * commons.crypto.cipher.transformation
     *
     * @param transformation the name of the transformation, e.g.,
     * <i>AES/CBC/PKCS5Padding</i>.
     * See the Java Cryptography Architecture Standard Algorithm Name Documentation
     * for information about standard transformation names.
     * @return CryptoCipher the cipher object (defaults to OpenSslCipher if available, else JceCipher)
     * @throws GeneralSecurityException if JCE cipher initialize failed
     */
    public static CryptoCipher getCryptoCipher(final String transformation)
            throws GeneralSecurityException {
        return getCryptoCipher(transformation, new Properties());
    }

    /**
     * Gets the cipher class.
     *
     * @param props The {@code Properties} class represents a set of
     *        properties.
     * @return the cipher class based on the props.
     */
    private static String getCipherClassString(final Properties props) {
        String cipherClassString = props.getProperty(CryptoCipherFactory.CLASSES_KEY, CLASSES_DEFAULT);
        if (cipherClassString.isEmpty()) { // TODO does it make sense to treat the empty string as the default?
            cipherClassString = CLASSES_DEFAULT;
        }
        return cipherClassString;
    }

}
