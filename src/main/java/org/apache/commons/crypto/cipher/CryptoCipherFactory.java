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
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

import org.apache.commons.crypto.utils.ReflectionUtils;
import org.apache.commons.crypto.utils.Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This is the factory class used for creating cipher class
 */
public class CryptoCipherFactory {

    /** LOG instance for {@link CryptoCipherFactory} */
    private final static Logger LOG = LoggerFactory
            .getLogger(CryptoCipherFactory.class);

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
        List<Class<? extends CryptoCipher>> klasses = getCipherClasses(props);
        CryptoCipher cipher = null;
        if (klasses != null) {
            for (Class<? extends CryptoCipher> klass : klasses) {
                try {
                    cipher = ReflectionUtils.newInstance(klass, props,
                            transformation);
                    if (cipher != null) {
                        LOG.debug("Using cipher {} for transformation {}.",
                                klass.getName(), transformation.getName());
                        break;
                    }
                } catch (Exception e) {
                    LOG.error(
                            "CryptoCipher {} is not available or transformation {} is not "
                                    + "supported.", klass.getName(),
                            transformation.getName());
                }
            }
        }

        return (cipher == null) ? new JceCipher(props, transformation) : cipher;
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

    // Return OpenSSLCipher if Properties is null or empty by default
    private static List<Class<? extends CryptoCipher>> getCipherClasses(
            Properties props) {
        List<Class<? extends CryptoCipher>> result = new ArrayList<Class<? extends CryptoCipher>>();
        String cipherClassString = Utils.getCipherClassString(props);

        for (String c : Utils.splitClassNames(cipherClassString, ",")) {
            try {
                Class<?> cls = ReflectionUtils.getClassByName(c);
                result.add(cls.asSubclass(CryptoCipher.class));
            } catch (ClassCastException e) {
                LOG.error("Class {} is not a CryptoCipher.", c);
            } catch (ClassNotFoundException e) {
                LOG.error("CryptoCipher {} not found.", c);
            }
        }

        return result;
    }

}
