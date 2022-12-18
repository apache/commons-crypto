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
package org.apache.commons.crypto.utils;

import javax.crypto.spec.SecretKeySpec;

/**
 * Creates AES objects
 *
 * @since 1.2.0
 */
public class AES {

    /** The AES algorithm name. */
    public static final String ALGORITHM = "AES";

    /**
     * Defines {@value}.
     */
    public static final String CBC_NO_PADDING = "AES/CBC/NoPadding";

    /**
     * Defines {@value}.
     */
    public static final String CBC_PKCS5_PADDING = "AES/CBC/PKCS5Padding";

    /**
     * Defines {@value}.
     */
    public static final String CTR_NO_PADDING = "AES/CTR/NoPadding";

    /**
     * Creates a new SecretKeySpec for the given key and {@link #ALGORITHM}.
     *
     * @param key a key.
     * @return a new SecretKeySpec.
     */
    public static SecretKeySpec newSecretKeySpec(final byte[] key) {
        return new SecretKeySpec(key, ALGORITHM);
    }

}
