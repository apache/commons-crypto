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
package org.apache.commons.crypto.cipher;

import java.security.NoSuchAlgorithmException;

 /**
  * Enumeration of Algorithm Mode.
  *
  * @since 1.1
  */
 public enum OpenSslAlgorithmMode {

     /**
      * Counter mode.
      */
     AES_CTR,
     /**
      * Cipher Block Chaining Mode
      */
     AES_CBC,
     /**
      * Galois/Counter Mode
      */
     AES_GCM;

     /**
      * Gets the OpenSslAlgorithmMode instance.
      *
      * @param algorithm the algorithm name
      * @param mode      the mode name
      * @return the {@code OpenSslAlgorithmMode} instance
      * @throws NoSuchAlgorithmException if the algorithm is not support
      */
     public static OpenSslAlgorithmMode get(final String algorithm, final String mode) throws NoSuchAlgorithmException {
         try {
             return valueOf(algorithm + "_" + mode);
         } catch (final Exception e) {
             throw new NoSuchAlgorithmException("Doesn't support algorithm: " + algorithm + " and mode: " + mode);
         }
     }
}
