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

import java.io.FileNotFoundException;
import java.lang.reflect.InvocationTargetException;
import java.security.GeneralSecurityException;
import java.util.Properties;

import org.junit.Assert;
import org.junit.Assume;
import org.junit.Test;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

public class OsCryptoRandomTest extends AbstractRandomTest {

    @Override
    public CryptoRandom getCryptoRandom() throws GeneralSecurityException {
        // Windows does not have a /dev/random device
        Assume.assumeTrue(!System.getProperty("os.name").contains("Windows"));
        final Properties props = new Properties();
        props.setProperty(
                CryptoRandomFactory.CLASSES_KEY,
                OsCryptoRandom.class.getName());
        final CryptoRandom random = CryptoRandomFactory.getCryptoRandom(props);
        assertTrue(
                "The CryptoRandom should be: " + OsCryptoRandom.class.getName(),
                random instanceof OsCryptoRandom);
        return random;
    }

    @Test
    public void testInvalidRandom() {
        final Properties props = new Properties();
        props.setProperty(CryptoRandomFactory.CLASSES_KEY, OsCryptoRandom.class.getName());
        // Invalid device
        props.setProperty(CryptoRandomFactory.DEVICE_FILE_PATH_KEY, "");
        try {
            CryptoRandomFactory.getCryptoRandom(props);
            fail("Expected GeneralSecurityException");
        } catch (final GeneralSecurityException e) {
            Throwable cause;
            cause = e.getCause();
            Assert.assertEquals(RuntimeException.class, cause.getClass());
            cause = cause.getCause();
            Assert.assertEquals(InvocationTargetException.class, cause.getClass());
            cause = cause.getCause();
            Assert.assertEquals(RuntimeException.class, cause.getClass());
            cause = cause.getCause();
            Assert.assertEquals(FileNotFoundException.class, cause.getClass());
        }
    }
}
