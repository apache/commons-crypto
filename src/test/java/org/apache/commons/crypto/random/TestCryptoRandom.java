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

import static org.junit.Assert.assertTrue;

import java.util.Properties;

import org.apache.commons.crypto.conf.ConfigurationKeys;
import org.junit.Test;

public class TestCryptoRandom {

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
    public void testEmptyFallback() throws Exception {
        final Properties props = new Properties();
        props.setProperty(ConfigurationKeys.SECURE_RANDOM_CLASSES_KEY, "");
        props.setProperty(ConfigurationKeys.ENABLE_FALLBACK_ON_NATIVE_FAILED_KEY, "");
        CryptoRandomFactory.getCryptoRandom(props);
    }

    @Test
    public void testTrueFallback() throws Exception {
        final Properties props = new Properties();
        props.setProperty(ConfigurationKeys.SECURE_RANDOM_CLASSES_KEY, "");
        props.setProperty(ConfigurationKeys.ENABLE_FALLBACK_ON_NATIVE_FAILED_KEY, "true");
        CryptoRandomFactory.getCryptoRandom(props);
    }

    @Test(expected=IllegalArgumentException.class)
    public void testFalseFallbackEmpty() throws Exception {
        final Properties props = new Properties();
        props.setProperty(ConfigurationKeys.SECURE_RANDOM_CLASSES_KEY, "");
        props.setProperty(ConfigurationKeys.ENABLE_FALLBACK_ON_NATIVE_FAILED_KEY, "notTrue");
        CryptoRandomFactory.getCryptoRandom(props);
    }

    @Test(expected=IllegalArgumentException.class)
    public void testFalseFallbackNoNames() throws Exception {
        final Properties props = new Properties();
        props.setProperty(ConfigurationKeys.SECURE_RANDOM_CLASSES_KEY, ",,,,");
        props.setProperty(ConfigurationKeys.ENABLE_FALLBACK_ON_NATIVE_FAILED_KEY, "notTrue");
        CryptoRandomFactory.getCryptoRandom(props);
    }

    @Test
    public void testNoSuchClass() throws Exception {
        final Properties props = new Properties();
        props.setProperty(ConfigurationKeys.SECURE_RANDOM_CLASSES_KEY, "noSuchClass");
        props.setProperty(ConfigurationKeys.ENABLE_FALLBACK_ON_NATIVE_FAILED_KEY, "notTrue");
        try {
            CryptoRandomFactory.getCryptoRandom(props);
        } catch (Exception e) {
            final String message = e.getMessage();
            assertTrue(message, message.contains("not found"));
            assertTrue(message, message.contains("noSuchClass"));
        }
    }

    @Test
    public void testWrongClass() throws Exception {
        final Properties props = new Properties();
        props.setProperty(ConfigurationKeys.SECURE_RANDOM_CLASSES_KEY, "java.util.Properties"); // Use a class that accepts a Properties object
        props.setProperty(ConfigurationKeys.ENABLE_FALLBACK_ON_NATIVE_FAILED_KEY, "notTrue");
        try {
            CryptoRandomFactory.getCryptoRandom(props);
        } catch (Exception e) {
            final String message = e.getMessage();
            assertTrue(message, message.contains("java.util.Properties"));
            assertTrue(message, message.contains("not a CryptoRandom"));
        }
    }

    @Test
    public void testWrongClassBadCtor() throws Exception {
        final Properties props = new Properties();
        final String canonicalName = DummyRandom.class.getCanonicalName();
        props.setProperty(ConfigurationKeys.SECURE_RANDOM_CLASSES_KEY, canonicalName);
        props.setProperty(ConfigurationKeys.ENABLE_FALLBACK_ON_NATIVE_FAILED_KEY, "notTrue");
        try {
            CryptoRandomFactory.getCryptoRandom(props);
        } catch (Exception e) {
            final String message = e.getMessage();
            assertTrue(message, message.contains(canonicalName));
            assertTrue(message, message.contains("NoSuchMethodException"));
        }
    }

    @Test
    public void testAbstractClass() throws Exception {
        final Properties props = new Properties();
        final String canonicalName = AbstractRandom.class.getCanonicalName();
        props.setProperty(ConfigurationKeys.SECURE_RANDOM_CLASSES_KEY, canonicalName);
        props.setProperty(ConfigurationKeys.ENABLE_FALLBACK_ON_NATIVE_FAILED_KEY, "notTrue");
        try {
            CryptoRandomFactory.getCryptoRandom(props);
        } catch (Exception e) {
            final String message = e.getMessage();
            assertTrue(message, message.contains(canonicalName));
            assertTrue(message, message.contains("NoSuchMethodException"));
        }
    }

}
