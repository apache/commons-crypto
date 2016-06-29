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

    @Test(expected=NullPointerException.class)
    public void testNull() throws Exception {
        CryptoRandomFactory.getCryptoRandom(null);
    }

    @Test
    public void testEmpty() throws Exception {
        final Properties props = new Properties();
        props.setProperty(ConfigurationKeys.SECURE_RANDOM_CLASSES_KEY, "");
        CryptoRandomFactory.getCryptoRandom(props);
    }


    @Test
    public void testDefaultRandom() throws GeneralSecurityException {
        Properties props = new Properties();
        CryptoRandom random = CryptoRandomFactory.getCryptoRandom(props);
        Assert.assertEquals(OpensslCryptoRandom.class.getName(),
            random.getClass().getName());
    }

    @Test
    public void testGetOSRandom() throws GeneralSecurityException {
        Properties props = new Properties();
        props.setProperty(
            ConfigurationKeys.SECURE_RANDOM_CLASSES_KEY,
            CryptoRandomFactory.RandomProvider.OS.getClassName());
        CryptoRandom random = CryptoRandomFactory.getCryptoRandom(props);

        Assert.assertEquals(OsCryptoRandom.class.getName(), random.getClass()
            .getName());
    }

    @Test
    public void testFullClassName() throws GeneralSecurityException {
        Properties props = new Properties();
        props.setProperty(
            ConfigurationKeys.SECURE_RANDOM_CLASSES_KEY,
            OsCryptoRandom.class.getName());
        CryptoRandom random = CryptoRandomFactory.getCryptoRandom(props);

        Assert.assertEquals(OsCryptoRandom.class.getName(), random.getClass()
            .getName());
    }

    @Test(expected = GeneralSecurityException.class)
    public void testInvalidRandom() throws GeneralSecurityException {
        Properties properties = new Properties();
        properties.setProperty(
            ConfigurationKeys.SECURE_RANDOM_CLASSES_KEY,
            "InvalidCipherName");
        CryptoRandomFactory.getCryptoRandom(properties);
    }

}
