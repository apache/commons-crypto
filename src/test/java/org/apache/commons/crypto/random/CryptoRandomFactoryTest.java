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

import java.lang.reflect.InvocationTargetException;
import java.security.GeneralSecurityException;
import java.util.Properties;

import org.junit.Assert;
import org.junit.Assume;
import org.junit.Test;

public class CryptoRandomFactoryTest {

    @Test(expected=NullPointerException.class)
    public void testNull() throws Exception {
        CryptoRandomFactory.getCryptoRandom(null);
    }

    @Test
    public void testEmpty() throws Exception {
        final Properties props = new Properties();
        props.setProperty(CryptoRandomFactory.CLASSES_KEY, "");
        CryptoRandomFactory.getCryptoRandom(props);
    }


    @Test
    public void testDefaultRandom() throws GeneralSecurityException {
        final Properties props = new Properties();
        final CryptoRandom random = CryptoRandomFactory.getCryptoRandom(props);
        final String name = random.getClass().getName();
        if (OpenSslCryptoRandom.isNativeCodeEnabled()) {
            Assert.assertEquals(OpenSslCryptoRandom.class.getName(), name);
        } else {
            Assert.assertEquals(JavaCryptoRandom.class.getName(), name);
        }
    }

    @Test
    public void testGetOSRandom() throws GeneralSecurityException {
        // Windows does not have a /dev/random device
        Assume.assumeTrue(!System.getProperty("os.name").contains("Windows"));
        final Properties props = new Properties();
        props.setProperty(
            CryptoRandomFactory.CLASSES_KEY,
            CryptoRandomFactory.RandomProvider.OS.getClassName());
        final CryptoRandom random = CryptoRandomFactory.getCryptoRandom(props);

        Assert.assertEquals(OsCryptoRandom.class.getName(), random.getClass()
            .getName());
    }

    @Test
    public void testFullClassName() throws GeneralSecurityException {
        final Properties props = new Properties();
        props.setProperty(
            CryptoRandomFactory.CLASSES_KEY,
            JavaCryptoRandom.class.getName());
        final CryptoRandom random = CryptoRandomFactory.getCryptoRandom(props);

        Assert.assertEquals(JavaCryptoRandom.class.getName(), random.getClass()
            .getName());
    }

    @Test(expected = GeneralSecurityException.class)
    public void testInvalidRandom() throws GeneralSecurityException {
        final Properties properties = new Properties();
        properties.setProperty(
            CryptoRandomFactory.CLASSES_KEY,
            "InvalidCipherName");
        CryptoRandomFactory.getCryptoRandom(properties);
    }

    @Test
    public void testInvalidRandomClass() throws GeneralSecurityException {
        final Properties properties = new Properties();
        properties.setProperty(
            "org.apache.commons.crypto.cipher",
            "OpenSsl");
        final CryptoRandom rand = CryptoRandomFactory.getCryptoRandom(properties);
        Assert.assertEquals(OpenSslCryptoRandom.class.getName(), rand.getClass().getName());
    }

    @Test
    public void testDefaultRandomClass() throws GeneralSecurityException {
        final CryptoRandom rand = CryptoRandomFactory.getCryptoRandom();
        Assert.assertEquals(OpenSslCryptoRandom.class.getName(), rand.getClass().getName());
    }

    @Test
    public void testAbstractRandom() {
        final Properties props = new Properties();
        props.setProperty(CryptoRandomFactory.CLASSES_KEY, AbstractRandom.class.getName());
        try {
            CryptoRandomFactory.getCryptoRandom(props);
            Assert.fail("Expected GeneralSecurityException");
        } catch (final GeneralSecurityException e) {
            final String message = e.getMessage();
            Assert.assertTrue(message, message.contains("InstantiationException"));
        }

    }

    @Test
    public void testDummmyRandom() {
        final Properties props = new Properties();
        props.setProperty(CryptoRandomFactory.CLASSES_KEY, DummyRandom.class.getName());
        try {
            CryptoRandomFactory.getCryptoRandom(props);
            Assert.fail("Expected GeneralSecurityException");
        } catch (final GeneralSecurityException e) {
            final String message = e.getMessage();
            Assert.assertTrue(message, message.contains("NoSuchMethodException"));
        }
    }

    @Test(expected=IllegalArgumentException.class)
    public void testNoClasses() throws Exception {
        final Properties props = new Properties();
        // An empty string currently means use the default
        // However the splitter drops empty fields
        props.setProperty(CryptoRandomFactory.CLASSES_KEY, ",");
        CryptoRandomFactory.getCryptoRandom(props);
    }

    @Test
    public void testFailingRandom() {
        final Properties props = new Properties();
        props.setProperty(CryptoRandomFactory.CLASSES_KEY, FailingRandom.class.getName());
        try {
            CryptoRandomFactory.getCryptoRandom(props);
            Assert.fail("Expected GeneralSecurityException");
        } catch (final GeneralSecurityException e) {
            Throwable cause = e.getCause();
            Assert.assertEquals(RuntimeException.class, cause.getClass());
            cause = cause.getCause();
            Assert.assertEquals(InvocationTargetException.class, cause.getClass());
            cause = cause.getCause();
            Assert.assertEquals(UnsatisfiedLinkError.class, cause.getClass());
        }
    }

}
