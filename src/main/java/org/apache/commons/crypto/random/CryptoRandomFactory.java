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
 * This is the factory class used for {@link CryptoRandom}.
 */
public class CryptoRandomFactory {

    /**
     * Defines the internal CryptoRandom implementations.
     * <p>
     * Usage:
     * <p>
     * <code>
     * props.setProperty(RANDOM_CLASSES_KEY, RandomProvider.OPENSSL
     *         .getClassName());
     * </code>
     */
    public enum RandomProvider {

        OPENSSL(OpensslCryptoRandom.class),
        JCE(JavaCryptoRandom.class),
        OS(OsCryptoRandom.class);

        private final Class<? extends CryptoRandom> klass;

        private final String className;

        /**
         * Constructs a RandomProvider.
         *
         * @param klass the implementation of provider
         */
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
     * The default value (OpensslCipher) for crypto cipher.
     */
    private static final String SECURE_RANDOM_CLASSES_DEFAULT = RandomProvider
        .OPENSSL.getClassName().concat(",").concat(RandomProvider.JCE
            .getClassName());

    /**
     * The private constructor of {@Link CryptoRandomFactory}.
     */
    private CryptoRandomFactory() {
    }

    /**
     * Gets a CryptoRandom instance for specified props.
     * Uses the SECURE_RANDOM_CLASSES_KEY from the provided
     * properties.
     * If it is not set, then it checks the System properties.
     * Failing that, it defaults to {@link JavaCryptoRandom}
     * The properties are passed to the generated class.
     *
     * @param props the configuration properties.
     * @return CryptoRandom  the cryptoRandom object.
     * @throws GeneralSecurityException if cannot create the {@link CryptoRandom} class
     * @throws IllegalArgumentException if no classname(s) are provided and fallback is disabled
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
        } else {
            if (errorMessage.length() == 0) {
                throw new IllegalArgumentException("No classname(s) provided");
            }
            throw new GeneralSecurityException(errorMessage.toString());
        }
    }

    /**
     * Gets the CryptoRandom class.
     *
     * @param props The <code>Properties</code> class represents a set of
     *        properties.
     * @return the CryptoRandom class based on the props.
     */
    private static String getRandomClassString(Properties props) {
        final String configName = ConfigurationKeys.SECURE_RANDOM_CLASSES_KEY;
        String randomClassString = Utils.getProperties(props)
            .getProperty(configName, SECURE_RANDOM_CLASSES_DEFAULT);
        if (randomClassString.isEmpty()) {
            randomClassString = SECURE_RANDOM_CLASSES_DEFAULT;
        }
        return randomClassString;
    }
}
