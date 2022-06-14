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
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.GeneralSecurityException;
import java.util.Properties;
import java.util.Random;

import org.apache.commons.crypto.utils.Utils;
import org.junit.jupiter.api.Test;

public class JavaCryptoRandomTest extends AbstractRandomTest {
    @Override
    public CryptoRandom getCryptoRandom() throws GeneralSecurityException {
        final Properties props = new Properties();
        props.setProperty(
                CryptoRandomFactory.CLASSES_KEY,
                JavaCryptoRandom.class.getName());
        final CryptoRandom random = CryptoRandomFactory.getCryptoRandom(props);
        assertTrue(
                random instanceof JavaCryptoRandom,
                "The CryptoRandom should be: " + JavaCryptoRandom.class.getName());
        return random;
    }

    @Test
    public void testNextIntIsntActuallyRandomNextInt() throws Exception {
    	final CryptoRandom cr = getCryptoRandom();
    	final Random r = (Random) cr;
    	final long seed = 1654421930011l; // System.getCurrentMillis() on 2022-June-05, 11:39
    	final Random otherRandom = new Random(seed);
    	final Random otherRandom2 = new Random();
    	otherRandom2.setSeed(seed);
    	r.setSeed(seed);
    	final long l1 = r.nextLong();
    	final long l2 = otherRandom.nextLong();
    	final long l3 = otherRandom2.nextLong();
    	assertEquals(l2, l3);
    	assertNotEquals(l1, l2);
    }
}
