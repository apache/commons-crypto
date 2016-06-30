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

import java.security.GeneralSecurityException;
import java.util.Properties;

import org.apache.commons.crypto.conf.ConfigurationKeys;
import org.apache.commons.crypto.utils.ReflectionUtils;
import org.apache.commons.crypto.utils.Utils;

/**
 * This is the factory class used for creating {@link CryptoRandom} instances
 */
public class CryptoRandomFactory {

    /**
     * Defines the internal CryptoRandom implementations.
     * <p>
     * Usage:
     * <p>
     * <blockquote><pre>
     * props.setProperty(RANDOM_CLASSES_KEY, RandomProvider.OPENSSL.getClassName());
     * props.setProperty(...); // if required by the implementation
     * random = CryptoRandomFactory.getCryptoRandom(transformation, props);
     * </pre></blockquote>
     */
    public enum RandomProvider {

        /**
         * The OpenSSL Random implementation (using JNI)
         * <p>
         * No properties are used for configuration, but they
         * are passed to the {@link RandomProvider#JAVA} backup implementation
         */
        // Please ensure the property description agrees with the implementation
        OPENSSL(OpenSslCryptoRandom.class),

        /**
         * The SecureRandom implementation from the JVM
         * <p>
         * Uses the property with key 
         * {@link ConfigurationKeys#SECURE_RANDOM_JAVA_ALGORITHM_KEY SECURE_RANDOM_JAVA_ALGORITHM_KEY}
         * with the default of 
         * {@link ConfigurationKeys#SECURE_RANDOM_JAVA_ALGORITHM_DEFAULT SECURE_RANDOM_JAVA_ALGORITHM_DEFAULT}
         */
        // Please ensure the property description agrees with the implementation
        JAVA(JavaCryptoRandom.class),

        /**
         * The OS random device implementation. May not be available on some OSes.
         * <p>
         * Uses {@link ConfigurationKeys#SECURE_RANDOM_DEVICE_FILE_PATH_KEY} to determine the
         * path to the random device, default is
         * {@link ConfigurationKeys#SECURE_RANDOM_DEVICE_FILE_PATH_DEFAULT}
         */
        // Please ensure the property description agrees with the implementation
        OS(OsCryptoRandom.class);

        private final Class<? extends CryptoRandom> klass;

        private final String className;

        private RandomProvider(Class<? extends CryptoRandom> klass) {
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
        public Class<? extends CryptoRandom> getImplClass() {
            return klass;
        }
    }

    /**
     * The default value (OPENSSL,JAVA) used when creating a {@link CryptoCipher}.
     */
    private static final String SECURE_RANDOM_CLASSES_DEFAULT = 
        RandomProvider.OPENSSL.getClassName()
        .concat(",")
        .concat(RandomProvider.JAVA.getClassName());

    /**
     * The private constructor of {@link CryptoRandomFactory}.
     */
    private CryptoRandomFactory() {
    }

    /**
     * Gets a CryptoRandom instance using the default implementation
     * as defined by {@link #SECURE_RANDOM_CLASSES_DEFAULT}
     *
     * @return CryptoRandom  the cryptoRandom object.
     * @throws GeneralSecurityException if cannot create the {@link CryptoRandom} class
     */
    public static CryptoRandom getCryptoRandom() throws GeneralSecurityException {
        Properties properties = new Properties();
        return getCryptoRandom(properties);
    }

    /**
     * Gets a CryptoRandom instance for specified props.
     * Uses the SECURE_RANDOM_CLASSES_KEY from the provided
     * properties.
     * If it is not set, then it checks the System properties.
     * Failing that, it defaults to OpenSslCryptoRandom,JavaCryptoRandom
     * The properties are passed to the generated class.
     *
     * @param props the configuration properties.
     * @return CryptoRandom  the cryptoRandom object.
     * @throws GeneralSecurityException if cannot create the {@link CryptoRandom} class
     * @throws IllegalArgumentException if no classname(s) are provided
     */
    public static CryptoRandom getCryptoRandom(Properties props)
            throws GeneralSecurityException {
        StringBuilder errorMessage = new StringBuilder();
        CryptoRandom random = null;
        for (String klassName : Utils.splitClassNames(
            getRandomClassString(props), ",")) {
            try {
                final Class<?> klass = ReflectionUtils.getClassByName(klassName);
                random = (CryptoRandom) ReflectionUtils.newInstance(klass, props);
                if (random != null) {
                    break;
                }
            } catch (ClassCastException e) {
                errorMessage.append("Class: [" + klassName + "] is not a CryptoRandom.");
            } catch (ClassNotFoundException e) {
                errorMessage.append("CryptoRandom: [" + klassName + "] not found.");
            }
        }

        if (random != null) {
            return random;
        }
        if (errorMessage.length() == 0) {
            throw new IllegalArgumentException("No classname(s) provided");
        }
        throw new GeneralSecurityException(errorMessage.toString());
    }

    /**
     * Get a OpenSSL CryptoRandom by default.
     *
     * @return CryptoRandom  the cryptoRandom object.
     * @throws GeneralSecurityException if OpenSSL is unavailable
     */
    public static CryptoRandom getCryptoRandom()
            throws GeneralSecurityException {
        Properties properties = new Properties();
        properties.put(ConfigurationKeys.SECURE_RANDOM_CLASSES_KEY,
                RandomProvider.OPENSSL.getClassName());
        return getCryptoRandom(properties);
    }

    /**
     * Gets the CryptoRandom class.
     *
     * @param props The <code>Properties</code> class represents a set of
     *        properties.
     * @return the CryptoRandom class based on the props.
     */
    private static String getRandomClassString(Properties props) {
        String randomClassString = props.getProperty(ConfigurationKeys.SECURE_RANDOM_CLASSES_KEY, SECURE_RANDOM_CLASSES_DEFAULT);
        if (randomClassString.isEmpty()) { // TODO does it make sense to treat the empty string as the default?
            randomClassString = SECURE_RANDOM_CLASSES_DEFAULT;
        }
        return randomClassString;
    }
}
