/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.commons.crypto.utils;

import javax.crypto.NoSuchPaddingException;

/**
 * Padding types.
 */
public enum Padding {

    /** Don't change the order of this enum value. */
    NoPadding,

    /** Don't change the order of this enum value. */
    PKCS5Padding;

    /**
     * Gets a Padding.
     *
     * @param padding the padding name.
     * @return a Padding instance.
     * @throws NoSuchPaddingException if the algorithm is not supported.
     */
    public static Padding get(final String padding) throws NoSuchPaddingException {
        try {
            return Padding.valueOf(padding);
        } catch (final Exception e) {
            throw new NoSuchPaddingException("Algorithm not supported: " + padding);
        }
    }

}