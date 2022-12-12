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

import java.security.NoSuchAlgorithmException;

import javax.crypto.NoSuchPaddingException;

/**
 * Transformation algorithm, mode and padding, in the format "Algorithm/Mode/Padding", for example "AES/CBC/NoPadding".
 *
 * @since 1.2.0
 */
public class Transformation {

    private static final int T_DELIM_PARTS = 3;
    private static final String T_DELIM_REGEX = "/";

    /**
     * Parses a transformation.
     *
     * @param transformation current transformation
     * @return the Transformation
     * @throws NoSuchAlgorithmException if the algorithm is not supported
     * @throws NoSuchPaddingException Thrown when the padding is unsupported.
     */
    public static Transformation parse(final String transformation) throws NoSuchAlgorithmException, NoSuchPaddingException {
        if (transformation == null) {
            throw new NoSuchAlgorithmException("No transformation given.");
        }

        //
        // Array containing the components of a Cipher transformation: index 0:
        // algorithm (e.g., AES) index 1: mode (e.g., CTR) index 2: padding (e.g.,
        // NoPadding)
        //
        final String[] parts = transformation.split(T_DELIM_REGEX, T_DELIM_PARTS + 1);
        if (parts.length != T_DELIM_PARTS) {
            throw new NoSuchAlgorithmException("Invalid transformation format: " + transformation);
        }
        return new Transformation(parts[0], parts[1], parts[2]);
    }

    private final String algorithm;
    private final String mode;
    private final Padding padding;

    /**
     * Constructs a new instance.
     *
     * @param algorithm the algorithm name
     * @param mode the mode name
     * @param padding the padding name
     */
    private Transformation(final String algorithm, final String mode, final Padding padding) {
        this.algorithm = algorithm;
        this.mode = mode;
        this.padding = padding;
    }

    /**
     * Constructs a new instance.
     *
     * @param algorithm the algorithm name
     * @param mode the mode name
     * @param padding the padding name
     * @throws NoSuchPaddingException Thrown when the padding is unsupported.
     */
    private Transformation(final String algorithm, final String mode, final String padding) throws NoSuchPaddingException {
        this(algorithm, mode, Padding.get(padding));
    }

    /**
     * Gets the algorithm.
     * 
     * @return the algorithm.
     */
    public String getAlgorithm() {
        return algorithm;
    }

    /**
     * Gets the mode.
     * 
     * @return the mode.
     */
    public String getMode() {
        return mode;
    }

    /**
     * Gets the padding.
     * 
     * @return the padding.
     */
    public Padding getPadding() {
        return padding;
    }
}