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

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.GeneralSecurityException;
import java.util.Properties;

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

}
