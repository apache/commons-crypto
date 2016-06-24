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
package org.apache.commons.crypto.examples;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.Properties;

import org.apache.commons.crypto.conf.ConfigurationKeys;
import org.apache.commons.crypto.random.CryptoRandom;
import org.apache.commons.crypto.random.CryptoRandomFactory;

public class RandomExample {

    /**
     * Main method
     *
     * @param args args of main
     * @throws GeneralSecurityException when encryption/decryption failed
     * @throws IOException when io failed
     */
    public static void main(String []args) throws GeneralSecurityException, IOException {
        //Constructs a byte array to store random data.
        byte[] key = new byte[16];
        byte[] iv = new byte[16];
        Properties properties = new Properties();
        properties.put(ConfigurationKeys.SECURE_RANDOM_CLASSES_KEY,
                "org.apache.commons.crypto.random.OpensslCryptoRandom"); // TODO replace with alias
        //Gets the 'CryptoRandom' instance.
        CryptoRandom random = CryptoRandomFactory.getCryptoRandom(properties);
        System.out.println(random.getClass().getCanonicalName());

        //Generates random bytes and places them into the byte array.
        random.nextBytes(key);
        random.nextBytes(iv);
        //Closes the CryptoRandom.
        random.close();

        // Show the output
        System.out.println(Arrays.toString(key));
        System.out.println(Arrays.toString(iv));
    }
}
