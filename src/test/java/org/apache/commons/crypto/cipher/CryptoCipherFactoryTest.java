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

import org.junit.Assert;
import org.junit.Test;

public class CryptoCipherFactoryTest {
    @Test
    public void testDefaultCipher() throws GeneralSecurityException {
        CryptoCipher defaultCipher = CryptoCipherFactory
                .getInstance("AES/CBC/NoPadding");
        Assert.assertEquals(OpensslCipher.class.getName(), defaultCipher
                .getClass().getName());
    }

    @Test
    public void testEmptyCipher() throws GeneralSecurityException {
        Properties properties = new Properties();
        properties.setProperty(
                ConfigurationKeys.COMMONS_CRYPTO_CIPHER_CLASSES_KEY, "");
        CryptoCipher defaultCipher = CryptoCipherFactory.getInstance(
                "AES/CBC/NoPadding", properties);
        Assert.assertEquals(OpensslCipher.class.getName(), defaultCipher
                .getClass().getName());
    }

    @Test
    public void testInvalidCipher() throws GeneralSecurityException {
        Properties properties = new Properties();
        properties.setProperty(ConfigurationKeys.COMMONS_CRYPTO_CIPHER_CLASSES_KEY,
                "InvalidCipherName");
        CryptoCipher defaultCipher = CryptoCipherFactory.getInstance(
                "AES/CBC/NoPadding", properties);
        Assert.assertEquals(JceCipher.class.getName(),
            defaultCipher.getClass().getName());
    }

    @Test(expected = GeneralSecurityException.class)
    public void testDisableFallback() throws GeneralSecurityException {
        Properties properties = new Properties();
        properties.setProperty(
                ConfigurationKeys.COMMONS_CRYPTO_CIPHER_CLASSES_KEY,
                "InvalidCipherName");
        properties.setProperty(ConfigurationKeys
            .COMMONS_CRYPTO_ENABLE_FALLBACK_ON_NATIVE_FAILED_KEY, "false");

        CryptoCipherFactory.getInstance("AES/CBC/NoPadding", properties);
    }

    @Test(expected = GeneralSecurityException.class)
    public void testInvalidTransformation() throws GeneralSecurityException {
      Properties properties = new Properties();
      CryptoCipherFactory.getInstance("AES/Invalid/NoPadding", properties);
    }
}
