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
     * The private constructor of {@Link CryptoRandomFactory}.
     */
    private CryptoRandomFactory() {
    }

    /**
     * This implementation of OpenSSL secure random using JNI.
     */
    public static final String OPENSSL_RANDOM = "OpensslCryptoRandom";

    /**
     * A CryptoRandom of Java implementation.
     */
    public static final String JAVA_RANDOM = "JavaCryptoRandom";

    /**
     * A Random implementation that uses random bytes sourced from the operating
     * system.
     */
    public static final String OS_FILE_RANDOM = "OsCryptoRandom";

    /**
     * Default package path of CryptoRandom.
     */
    private static final String RANDOM_PROVIDER_DEFAULT_PACKAGE = CryptoRandomFactory
        .class.getPackage().getName();

    /**
     * Gets a CryptoRandom instance for specified props.
     * Uses the COMMONS_CRYPTO_SECURE_RANDOM_CLASSES_KEY from the provided
     * properties.
     *
     * The value of COMMONS_CRYPTO_SECURE_RANDOM_CLASSES_KEY could be {@link
     * #JAVA_RANDOM}, {@link #OS_FILE_RANDOM}, {@link #OPENSSL_RANDOM} or
     * full class name of CryptoRandom's implementation.
     *
     * If it is not set, then it checks the System properties.
     * Failing that, it defaults to JavaCryptoRandom
     * The properties are passed to the generated class.
     *
     * @param props the configuration properties.
     * @return CryptoRandom the cryptoRandom object.Null value will be returned
     *         if no CryptoRandom classes with props.
     * @throws GeneralSecurityException if fail to create the
     *         {@link CryptoRandom}.
     */
    public static CryptoRandom getCryptoRandom(Properties props)
            throws GeneralSecurityException {
        String cryptoRandomClasses = getCryptoRandomClassString(props);

        StringBuilder errorMessage = new StringBuilder();
        CryptoRandom random = null;
        if (cryptoRandomClasses != null) {
            for (String klassName : Utils.splitClassNames(cryptoRandomClasses,
                    ",")) {
                try {
                    Class<?> klass;
                    if (klassName.contains(".")) {
                        // If the class is not in default package, treat the
                        // class as full class name and load again.
                        klass = ReflectionUtils.getClassByName(klassName);
                    } else {
                        // Load the class is default package.
                        klass = ReflectionUtils.getClassByName(
                            RANDOM_PROVIDER_DEFAULT_PACKAGE + "." + klassName);
                    }
                    random = (CryptoRandom) ReflectionUtils.newInstance(klass, props);
                    if (random != null) {
                        break;
                    }
                } catch (ClassCastException e) {
                    errorMessage.append("Class: [" + klassName + "] is not a " +
                            "CryptoCipher.");
                } catch (ClassNotFoundException e) {
                    errorMessage.append("CryptoCipher: [" + klassName + "] " +
                            "not " + "found.");
                }
            }
        }

        if (random != null) {
            return random;
        } else if (Utils.isFallbackEnabled(props)) {
            return  new JavaCryptoRandom(props);
        } else {
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
    private static String getCryptoRandomClassString(Properties props) {
        final String configName = ConfigurationKeys.COMMONS_CRYPTO_SECURE_RANDOM_CLASSES_KEY;
        String cryptoRandomClasses = props.getProperty(configName) != null ? props
            .getProperty(configName, ConfigurationKeys.COMMONS_CRYPTO_SECURE_RANDOM_CLASSES_DEFAULT)
            : System.getProperty(configName,
            ConfigurationKeys.COMMONS_CRYPTO_SECURE_RANDOM_CLASSES_DEFAULT);
        if (cryptoRandomClasses.isEmpty()) {
            cryptoRandomClasses = ConfigurationKeys.COMMONS_CRYPTO_SECURE_RANDOM_CLASSES_DEFAULT;
        }
        return cryptoRandomClasses;
    }
}
