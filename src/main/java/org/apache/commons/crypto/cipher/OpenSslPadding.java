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

import javax.crypto.NoSuchPaddingException;


 /**
  * Enumeration of Algorithm Padding.
  *
  * @since 1.1
  */
public enum OpenSslPadding {
     /**
      * No padding.
      */
    NO_PADDING ("NoPadding"),
     /**
      * PKCS5 Padding
      */
    PKCS5_PADDING ("PKCS5Padding");

     /** The enumeration name. */
     private final String padding;

    /**
     * Constructs a new instance.
     */
     OpenSslPadding(final String padding) {
         this.padding = padding;
     }
     /**
     * Gets the Padding Ordinal value.
     *
     * @param padding the padding to find.
     * @return the value of ordinal Padding.
     * @throws NoSuchPaddingException if the padding is not available.
     */
    public static int get(final String padding) throws NoSuchPaddingException {
        return forName(padding).ordinal();
    }
     /**
      * Factory method to create an OpenSslPadding from a padding.
      *
      * @param padding the padding to find.
      * @return the OpenSslPadding object
      * @throws NoSuchPaddingException if the padding is not available.
      */
     public static OpenSslPadding forName(final String padding) throws NoSuchPaddingException {
         for (final OpenSslPadding paddingCase : OpenSslPadding.values()) {
             if (paddingCase.getPadding().equals(padding)) {
                 return paddingCase;
             }
         }
         throw new NoSuchPaddingException("Invalid Padding padding: " + padding);
     }

     /**
      * Gets the name of the padding.
      *
      * @return the name of the padding
      */
     public String getPadding() {
         return padding;
     }
 }
