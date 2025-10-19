/*
* Licensed to the Apache Software Foundation (ASF) under one
* or more contributor license agreements.  See the NOTICE file
* distributed with this work for additional information
* regarding copyright ownership.  The ASF licenses this file
* to you under the Apache License, Version 2.0 (the
* "License"); you may not use this file except in compliance
* with the License.  You may obtain a copy of the License at
*
*     https://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/
package org.apache.commons.crypto.random;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.security.GeneralSecurityException;
import java.util.Properties;

import org.apache.commons.lang3.SystemProperties;
import org.junit.jupiter.api.Test;

class CryptoRandomFactoryTest {

    @Test
    void testAbstractRandom() {
        final Properties properties = new Properties();
        properties.setProperty(CryptoRandomFactory.CLASSES_KEY, AbstractRandom.class.getName());
        final Exception ex = assertThrows(GeneralSecurityException.class, () -> CryptoRandomFactory.getCryptoRandom(properties));
        final String message = ex.getMessage();
        assertTrue(message.contains("InstantiationException"), message);
    }

    @Test
    void testDefaultRandom() throws GeneralSecurityException, IOException {
        final Properties properties = new Properties();
        try (final CryptoRandom random = CryptoRandomFactory.getCryptoRandom(properties)) {
            final String name = random.getClass().getName();
            if (OpenSslCryptoRandom.isNativeCodeEnabled()) {
                assertEquals(OpenSslCryptoRandom.class.getName(), name);
            } else {
                assertEquals(JavaCryptoRandom.class.getName(), name);
            }
        }
    }

    @Test
    void testDefaultRandomClass() throws GeneralSecurityException, IOException {
        try (final CryptoRandom random = CryptoRandomFactory.getCryptoRandom()) {
            assertEquals(OpenSslCryptoRandom.class.getName(), random.getClass().getName());
        }
    }

    @Test
    void testMissingPropertyCtrRandomRandom() {
        final Properties properties = new Properties();
        properties.setProperty(CryptoRandomFactory.CLASSES_KEY, MissingPropertyCtrRandom.class.getName());
        final Exception ex = assertThrows(GeneralSecurityException.class, () -> CryptoRandomFactory.getCryptoRandom(properties));
        final String message = ex.getMessage();
        assertTrue(message.contains("NoSuchMethodException"), message);
    }

    @Test
    void testEmpty() throws Exception {
        final Properties properties = new Properties();
        properties.setProperty(CryptoRandomFactory.CLASSES_KEY, "");
        CryptoRandomFactory.getCryptoRandom(properties).close();
    }

    @Test
    void testExceptionInInitializerErrorRandom() throws GeneralSecurityException, IOException {
        final Properties properties = new Properties();
        final String classes = ExceptionInInitializerErrorRandom.class.getName().concat(",")
            .concat(CryptoRandomFactory.RandomProvider.JAVA.getClassName());
        properties.setProperty(CryptoRandomFactory.CLASSES_KEY, classes);
        // Invoke 3 times to test the reentrancy of the method in the scenario of class initialization failure.
        for (int i = 0; i < 3; i++) {
            try (final CryptoRandom random = CryptoRandomFactory.getCryptoRandom(properties)) {
                assertEquals(JavaCryptoRandom.class.getName(), random.getClass().getName());
            }
        }
    }

    @Test
    void testFailingRandom() {
        final Properties properties = new Properties();
        properties.setProperty(CryptoRandomFactory.CLASSES_KEY, FailingRandom.class.getName());
        final Exception ex = assertThrows(GeneralSecurityException.class, () -> CryptoRandomFactory.getCryptoRandom(properties));

        Throwable cause = ex.getCause();
        assertEquals(IllegalArgumentException.class, cause.getClass());
        cause = cause.getCause();
        assertEquals(InvocationTargetException.class, cause.getClass());
        cause = cause.getCause();
        assertEquals(UnsatisfiedLinkError.class, cause.getClass());
    }

    @Test
    void testFullClassName() throws GeneralSecurityException, IOException {
        final Properties props = new Properties();
        props.setProperty(CryptoRandomFactory.CLASSES_KEY, JavaCryptoRandom.class.getName());
        try (final CryptoRandom random = CryptoRandomFactory.getCryptoRandom(props)) {
            assertEquals(JavaCryptoRandom.class.getName(), random.getClass().getName());
        }
    }

    @Test
    void testGetOSRandom() throws GeneralSecurityException, IOException {
        // Windows does not have a /dev/random device
        assumeTrue(!SystemProperties.getOsName().contains("Windows"));
        final Properties properties = new Properties();
        properties.setProperty(CryptoRandomFactory.CLASSES_KEY, CryptoRandomFactory.RandomProvider.OS.getClassName());
        try (final CryptoRandom random = CryptoRandomFactory.getCryptoRandom(properties)) {
            assertEquals(OsCryptoRandom.class.getName(), random.getClass().getName());
        }
    }

    @Test
    void testInvalidRandom() {
        final Properties properties = new Properties();
        properties.setProperty(CryptoRandomFactory.CLASSES_KEY, "InvalidCipherName");

        assertThrows(GeneralSecurityException.class, () -> CryptoRandomFactory.getCryptoRandom(properties));
    }

    @Test
    void testInvalidRandomClass() throws GeneralSecurityException, IOException {
        final Properties properties = new Properties();
        properties.setProperty("org.apache.commons.crypto.cipher", "OpenSsl");
        try (final CryptoRandom random = CryptoRandomFactory.getCryptoRandom(properties)) {
            assertEquals(OpenSslCryptoRandom.class.getName(), random.getClass().getName());
        }
    }

    @Test
    void testNoClasses() {
        final Properties properties = new Properties();
        // An empty string currently means use the default
        // However the splitter drops empty fields
        properties.setProperty(CryptoRandomFactory.CLASSES_KEY, ",");
        assertThrows(IllegalArgumentException.class, () -> CryptoRandomFactory.getCryptoRandom(properties));
    }

    @Test
    void testNull() {
        assertThrows(NullPointerException.class, () -> CryptoRandomFactory.getCryptoRandom(null));
    }
}
