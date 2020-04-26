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

import java.security.NoSuchAlgorithmException;

import javax.crypto.Cipher;

import org.junit.Assert;
import org.junit.BeforeClass;

public class JceCipherTest extends AbstractCipherTest {

    private static final int MAX_KEY_LEN_LOWER_BOUND = 256;

    @Override
    public void init() {
        transformations = new String[] {
                "AES/CBC/NoPadding",
                "AES/CBC/PKCS5Padding",
                "AES/CTR/NoPadding"};
        cipherClass = JCE_CIPHER_CLASSNAME;
    }

    @BeforeClass
    public static void checkJceUnlimitedStrength() throws NoSuchAlgorithmException {
        final int maxKeyLen = Cipher.getMaxAllowedKeyLength("AES");
        Assert.assertTrue(String.format(
                "Testing requires support for an AES key length of %d, but " +
                "the detected maximum key length is %d.  This may indicate " +
                "that the test environment is missing the JCE Unlimited " +
                "Strength Jurisdiction Policy Files.",
                MAX_KEY_LEN_LOWER_BOUND, maxKeyLen),
                maxKeyLen >= MAX_KEY_LEN_LOWER_BOUND);
    }
}
