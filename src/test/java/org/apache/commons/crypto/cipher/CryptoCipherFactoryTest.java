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

import org.junit.Assert;
import org.junit.Test;

public class CryptoCipherFactoryTest {
    @Test
    public void testDefaultCipher() throws GeneralSecurityException {
        final CryptoCipher defaultCipher = CryptoCipherFactory
                .getCryptoCipher("AES/CBC/NoPadding");
        final String name = defaultCipher.getClass().getName();
        if (OpenSsl.getLoadingFailureReason() == null) {
            Assert.assertEquals(OpenSslCipher.class.getName(), name);
        } else {
            Assert.assertEquals(JceCipher.class.getName(), name);
        }
    }

    @Test
    public void testEmptyCipher() throws GeneralSecurityException {
        final Properties properties = new Properties();
        properties.setProperty(CryptoCipherFactory.CLASSES_KEY, ""); // TODO should this really mean use the default?
        final CryptoCipher defaultCipher = CryptoCipherFactory.getCryptoCipher(
                "AES/CBC/NoPadding", properties);
        final String name = defaultCipher.getClass().getName();
        if (OpenSsl.getLoadingFailureReason() == null) {
            Assert.assertEquals(OpenSslCipher.class.getName(), name);
        } else {
            Assert.assertEquals(JceCipher.class.getName(), name);
        }
    }

    @Test(expected = GeneralSecurityException.class)
    public void testInvalidCipher() throws GeneralSecurityException {
        final Properties properties = new Properties();
        properties.setProperty(CryptoCipherFactory.CLASSES_KEY,
                "InvalidCipherName");
        CryptoCipherFactory.getCryptoCipher("AES/CBC/NoPadding", properties);
    }

    @Test(expected = GeneralSecurityException.class)
    public void testInvalidTransformation() throws GeneralSecurityException {
      final Properties properties = new Properties();
      CryptoCipherFactory.getCryptoCipher("AES/Invalid/NoPadding", properties);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testNoCipher() throws Exception {
        final Properties properties = new Properties();
        // An empty string currently means use the default
        // However the splitter drops empty fields
        properties.setProperty(CryptoCipherFactory.CLASSES_KEY, ",");
        CryptoCipherFactory.getCryptoCipher("AES/CBC/NoPadding", properties);
    }

}
