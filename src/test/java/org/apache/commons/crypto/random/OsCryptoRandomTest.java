 /*
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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.io.FileNotFoundException;
import java.lang.reflect.InvocationTargetException;
import java.security.GeneralSecurityException;
import java.util.Properties;

import org.apache.commons.lang3.SystemProperties;
import org.junit.jupiter.api.Test;

public class OsCryptoRandomTest extends AbstractRandomTest {

    @Override
    public CryptoRandom getCryptoRandom() throws GeneralSecurityException {
        // Windows does not have a /dev/random device
        assumeTrue(!SystemProperties.getOsName().contains("Windows"));
        final Properties props = new Properties();
        props.setProperty(CryptoRandomFactory.CLASSES_KEY, OsCryptoRandom.class.getName());
        final CryptoRandom random = CryptoRandomFactory.getCryptoRandom(props);
        assertInstanceOf(OsCryptoRandom.class, random, "The CryptoRandom should be: " + OsCryptoRandom.class.getName());
        return random;
    }

    @Test
    public void testInvalidRandom() {
        final Properties props = new Properties();
        props.setProperty(CryptoRandomFactory.CLASSES_KEY, OsCryptoRandom.class.getName());
        // Invalid device
        props.setProperty(CryptoRandomFactory.DEVICE_FILE_PATH_KEY, "");
        final Exception e = assertThrows(GeneralSecurityException.class, () -> CryptoRandomFactory.getCryptoRandom(props));
        Throwable cause;
        cause = e.getCause();
        assertEquals(IllegalArgumentException.class, cause.getClass());
        cause = cause.getCause();
        assertEquals(InvocationTargetException.class, cause.getClass());
        cause = cause.getCause();
        assertEquals(IllegalArgumentException.class, cause.getClass());
        cause = cause.getCause();
        assertEquals(FileNotFoundException.class, cause.getClass());

    }
}
