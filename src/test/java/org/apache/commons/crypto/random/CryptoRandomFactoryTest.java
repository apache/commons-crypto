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
import org.junit.Assert;
import org.junit.Test;

public class CryptoRandomFactoryTest {

    @Test
    public void testDefaultRandom() throws GeneralSecurityException {
        Properties props = new Properties();
        CryptoRandom random = CryptoRandomFactory.getCryptoRandom(props);

        Assert.assertEquals(OpensslCryptoRandom.class.getName(), random.getClass()
                .getName());
    }

    @Test
    public void testEmptyRandom() throws GeneralSecurityException {
        Properties props = new Properties();
        props.setProperty(
                ConfigurationKeys.COMMONS_CRYPTO_SECURE_RANDOM_CLASSES_KEY, "");
        CryptoRandom random = CryptoRandomFactory.getCryptoRandom(props);

        Assert.assertEquals(OpensslCryptoRandom.class.getName(), random
                .getClass().getName());
    }

    @Test
    public void testShortClassName() throws GeneralSecurityException {
        Properties props = new Properties();
        props.setProperty(
                ConfigurationKeys.COMMONS_CRYPTO_SECURE_RANDOM_CLASSES_KEY,
                CryptoRandomFactory.OS_FILE_RANDOM);
        CryptoRandom random = CryptoRandomFactory.getCryptoRandom(props);

        Assert.assertEquals(OsCryptoRandom.class.getName(), random.getClass()
                .getName());
    }

    @Test
    public void testFullClassName() throws GeneralSecurityException {
        Properties props = new Properties();
        props.setProperty(
                ConfigurationKeys.COMMONS_CRYPTO_SECURE_RANDOM_CLASSES_KEY,
                OsCryptoRandom.class.getName());
        CryptoRandom random = CryptoRandomFactory.getCryptoRandom(props);

        Assert.assertEquals(OsCryptoRandom.class.getName(), random.getClass()
                .getName());
    }

    @Test
    public void testInvalidRandom() throws GeneralSecurityException {
        Properties properties = new Properties();
        properties.setProperty(
                ConfigurationKeys.COMMONS_CRYPTO_SECURE_RANDOM_CLASSES_KEY,
                "InvalidCipherName");
        CryptoRandom random = CryptoRandomFactory.getCryptoRandom(properties);
        Assert.assertEquals(JavaCryptoRandom.class.getName(), random.getClass()
                .getName());
    }

    @Test(expected = GeneralSecurityException.class)
    public void testDisableFallback() throws GeneralSecurityException {
        Properties properties = new Properties();
        properties.setProperty(
                ConfigurationKeys.COMMONS_CRYPTO_SECURE_RANDOM_CLASSES_KEY,
                "InvalidCipherName");
        properties
                .setProperty(
                        ConfigurationKeys.COMMONS_CRYPTO_ENABLE_FALLBACK_ON_NATIVE_FAILED_KEY,
                        "false");

        CryptoRandomFactory.getCryptoRandom(properties);
    }
}
