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
package org.apache.commons.crypto.jna;

import java.security.GeneralSecurityException;
import java.util.Properties;

import org.apache.commons.crypto.jna.OpenSslJnaCryptoRandom;
import org.apache.commons.crypto.random.AbstractRandomTest;
import org.apache.commons.crypto.random.CryptoRandom;
import org.apache.commons.crypto.random.CryptoRandomFactory;
import org.junit.Assume;
import org.junit.Before;

import static org.junit.Assert.assertTrue;

public class OpenSslJnaCryptoRandomTest extends AbstractRandomTest {

    @Before
    public void init() {
        Assume.assumeTrue(OpenSslJna.isEnabled());
    }

    @Override
    public CryptoRandom getCryptoRandom() throws GeneralSecurityException {
        final Properties props = new Properties();
        props.setProperty(
                CryptoRandomFactory.CLASSES_KEY,
                OpenSslJnaCryptoRandom.class.getName());
        final CryptoRandom random = CryptoRandomFactory.getCryptoRandom(props);
        assertTrue(
                "The CryptoRandom should be: " + OpenSslJnaCryptoRandom.class.getName(),
                random instanceof OpenSslJnaCryptoRandom);
        return random;
    }

}
