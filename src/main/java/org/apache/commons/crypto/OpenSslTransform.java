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
package org.apache.commons.crypto;

 /**
  *
  * Utility code for dealing with different algorithms,modes and types.
  * <p>
  * The {@code OpenSslTransform} class provide information about the operation to be performed on the given input.
  * It is necessary to deal with the modes, padding and the algorithm.
  * </p>
  *
  *  <ul>
  *    <li><b>algorithm</b> (e.g., AES)</li>
  *    <li><b>mode</b>      (e.g., CTR)</li>
  *    <li><b>padding</b>   (e.g., PKCS5Padding)</li>
  *  </ul>
  *
  * @since 1.1
  */
public class OpenSslTransform {
    final String algorithm;
    final String mode;
    final String padding;

    /**
     * Constructor of Transform.
     *
     * @param algorithm the algorithm name
     * @param mode      the mode name
     * @param padding   the padding name
     */
    public OpenSslTransform(final String algorithm, final String mode, final String padding) {
        this.algorithm = algorithm;
        this.mode = mode;
        this.padding = padding;
    }
    /**
     * Gets the algorithm name.
     *
     * @return the algorithm name
     */
    public String getAlgorithm() {
        return algorithm;
    }
    /**
     * Gets the mode name.
     *
     * @return the mode name
     */
    public String getMode() {
        return mode;
    }
    /**
     * Gets the padding name.
     *
     * @return the padding name
     */
    public String getPadding() {
        return padding;
    }
}
