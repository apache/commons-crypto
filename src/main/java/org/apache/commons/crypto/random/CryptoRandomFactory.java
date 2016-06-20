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

import org.apache.commons.crypto.utils.ReflectionUtils;
import org.apache.commons.crypto.utils.Utils;
import static org.apache.commons.crypto.conf.ConfigurationKeys.COMMONS_CRYPTO_SECURE_RANDOM_CLASSES_KEY;

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
     * Gets a CryptoRandom instance for specified props.
     * Uses the COMMONS_CRYPTO_SECURE_RANDOM_CLASSES_KEY from the provided 
     * properties.
     * If it is not set, then it checks the System properties.
     * Failing that, it defaults to {@link JavaCryptoRandom}
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
        String cryptoRandomClasses = props
                .getProperty(COMMONS_CRYPTO_SECURE_RANDOM_CLASSES_KEY);
        if (cryptoRandomClasses == null) {
            cryptoRandomClasses = System
                    .getProperty(COMMONS_CRYPTO_SECURE_RANDOM_CLASSES_KEY);
        }

        StringBuilder errorMessage = new StringBuilder();
        CryptoRandom random = null;
        if (cryptoRandomClasses != null) {
            for (String klassName : Utils.splitClassNames(cryptoRandomClasses,
                    ",")) {
                try {
                    final Class<?> klass = ReflectionUtils
                            .getClassByName(klassName);
                    random = (CryptoRandom) ReflectionUtils.newInstance(klass,
                            props);
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
        } else if (Utils.isFallbackEnable(props)) {
            return  new JavaCryptoRandom(props);
        } else {
            throw new GeneralSecurityException(errorMessage.toString());
        }
    }
}
