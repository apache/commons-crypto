/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * 
 */
package org.apache.commons.crypto.jna;

import org.apache.commons.crypto.cipher.CryptoCipher;
import org.apache.commons.crypto.random.CryptoRandom;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.IOException;

/**
 * Public class to give access to the package protected class objects
 */
public final class OpenSslJna {

    /**
    * @return installed openSSL version is 1.1 or not
    */ 
    static boolean isOpenSSLVersion_1_1() {
        String line = " ";
        try {
            Process process = Runtime.getRuntime().exec("openssl version");
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            line = reader.readLine();
            reader.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return line.matches("OpenSSL 1.1(.*)");
    }

    /**
     * @return The cipher class of JNA implementation
     */
    public static Class<? extends CryptoCipher> getCipherClass() {
        if (isOpenSSLVersion_1_1()) {
            return OpenSslJnaCipher_1_1.class;
        }  else {
            return OpenSslJnaCipher.class;
        }
    }

    /**
     * @return The random class of JNA implementation
     */
    public static Class<? extends CryptoRandom> getRandomClass() {
        if (isOpenSSLVersion_1_1()) {
            return OpenSslJnaCryptoRandom_1_1.class;
        } else {
            return OpenSslJnaCryptoRandom.class;
        }
    }

    /**
     * @return true if JNA native loads successfully
     */
    public static boolean isEnabled() {
        if (isOpenSSLVersion_1_1()) {
            return OpenSslNativeJna_1_1.INIT_OK;
        } else {
            return OpenSslNativeJna.INIT_OK;
        }
    }

    /**
     * @return the error of JNA
     */
    public static Throwable initialisationError() {
        if (isOpenSSLVersion_1_1()) {
            return OpenSslNativeJna_1_1.INIT_ERROR;
        } else {
            return OpenSslNativeJna.INIT_ERROR;
        }
    }
}
