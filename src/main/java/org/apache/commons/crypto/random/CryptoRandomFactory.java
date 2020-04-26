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
import java.util.List;
import java.util.Properties;

import org.apache.commons.crypto.Crypto;
import org.apache.commons.crypto.utils.ReflectionUtils;
import org.apache.commons.crypto.utils.Utils;

/**
 * This is the factory class used for creating {@link CryptoRandom} instances
 */
public class CryptoRandomFactory {

    // security random related configuration keys
    /**
     * The configuration key of the file path for secure random device.
     */
    public static final String DEVICE_FILE_PATH_KEY = Crypto.CONF_PREFIX
            + "secure.random.device.file.path";

    /**
     * The default value ({@value}) of the file path for secure random device.
     */
    // Note: this is public mainly for use by the Javadoc
    public static final String DEVICE_FILE_PATH_DEFAULT = "/dev/urandom";

    /**
     * The configuration key of the algorithm of secure random.
     */
    public static final String JAVA_ALGORITHM_KEY = Crypto.CONF_PREFIX
            + "secure.random.java.algorithm";

    /**
     * The default value ({@value}) of the algorithm of secure random.
     */
    // Note: this is public mainly for use by the Javadoc
    public static final String JAVA_ALGORITHM_DEFAULT = "SHA1PRNG";

    /**
     * The configuration key of the CryptoRandom implementation class.
     * <p>
     * The value of the CLASSES_KEY needs to be the full name of a
     * class that implements the
     * {@link org.apache.commons.crypto.random.CryptoRandom CryptoRandom} interface
     * The internal classes are listed in the enum
     * {@link RandomProvider RandomProvider}
     * which can be used to obtain the full class name.
     * <p>
     * The value can also be a comma-separated list of class names in
     * order of descending priority.
     */
    public static final String CLASSES_KEY = Crypto.CONF_PREFIX
            + "secure.random.classes";
    /**
     * Defines the internal CryptoRandom implementations.
     * <p>
     * Usage:
     * <blockquote><pre>
     * props.setProperty(CryptoRandomFactory.CLASSES_KEY, RandomProvider.OPENSSL.getClassName());
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
         * {@link #JAVA_ALGORITHM_KEY}
         * with the default of
         * {@link #JAVA_ALGORITHM_DEFAULT}
         */
        // Please ensure the property description agrees with the implementation
        JAVA(JavaCryptoRandom.class),

        /**
         * The OS random device implementation. May not be available on some OSes.
         * <p>
         * Uses {@link #DEVICE_FILE_PATH_KEY} to determine the
         * path to the random device, default is
         * {@link #DEVICE_FILE_PATH_DEFAULT}
         */
        // Please ensure the property description agrees with the implementation
        OS(OsCryptoRandom.class);

        private final Class<? extends CryptoRandom> klass;

        private final String className;

        /**
         * The private constructor.
         * @param klass the Class of CryptoRandom
         */
        private RandomProvider(final Class<? extends CryptoRandom> klass) {
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
     * The default value (OPENSSL,JAVA) used when creating a {@link org.apache.commons.crypto.cipher.CryptoCipher}.
     */
    private static final String CLASSES_DEFAULT =
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
     * as defined by {@link #CLASSES_DEFAULT}
     *
     * @return CryptoRandom  the cryptoRandom object.
     * @throws GeneralSecurityException if cannot create the {@link CryptoRandom} class
     */
    public static CryptoRandom getCryptoRandom() throws GeneralSecurityException {
        final Properties properties = new Properties();
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
    public static CryptoRandom getCryptoRandom(final Properties props)
            throws GeneralSecurityException {
        final List<String> names = Utils.splitClassNames(getRandomClassString(props), ",");
        if (names.size() == 0) {
            throw new IllegalArgumentException("No classname(s) provided");
        }
        final StringBuilder errorMessage = new StringBuilder();
        CryptoRandom random = null;
        Exception lastException = null;
        for (final String klassName : names) {
            try {
                final Class<?> klass = ReflectionUtils.getClassByName(klassName);
                random = (CryptoRandom) ReflectionUtils.newInstance(klass, props);
                if (random != null) {
                    break;
                }
            } catch (final ClassCastException e) {
                lastException = e;
                errorMessage.append("Class: [" + klassName + "] is not a CryptoRandom.");
            } catch (final ClassNotFoundException e) {
                lastException = e;
                errorMessage.append("CryptoRandom: [" + klassName + "] not found.");
            } catch (final Exception e) {
                lastException = e;
                errorMessage.append("CryptoRandom: [" + klassName + "] failed with " + e.getMessage());
            }
        }

        if (random != null) {
            return random;
        }
        throw new GeneralSecurityException(errorMessage.toString(), lastException);
    }

    /**
     * Gets the CryptoRandom class.
     *
     * @param props The {@code Properties} class represents a set of
     *        properties.
     * @return the CryptoRandom class based on the props.
     */
    private static String getRandomClassString(final Properties props) {
        String randomClassString = props.getProperty(CryptoRandomFactory.CLASSES_KEY, CLASSES_DEFAULT);
        if (randomClassString.isEmpty()) { // TODO does it make sense to treat the empty string as the default?
            randomClassString = CLASSES_DEFAULT;
        }
        return randomClassString;
    }
}
