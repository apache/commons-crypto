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
package com.intel.chimera.cipher;

/**
 * Defines properties of a CipherTransformation. Modeled after the ciphers in
 * {@link javax.crypto.Cipher}.
 */
public enum CipherTransformation {

  /** A crypto transformation representing AES/CTR/NoPadding */
  AES_CTR_NOPADDING("AES/CTR/NoPadding", 16),
  /** A crypto transformation representing AES/CBC/NoPadding */
  AES_CBC_NOPADDING("AES/CBC/NoPadding", 16),
  /** A crypto transformation representing AES/CBC/PKCS5Padding */
  AES_CBC_PKCS5PADDING("AES/CBC/PKCS5Padding", 16);

  private final String name;
  private final int algorithmBlockSize;

  /**
   * Constructor for CipherTransformation.  Initalizes the cipher with algorithm
   * name and block size of the algorithm.
   *
   * @param name the name of cipher algorithm
   * @param algorithmBlockSize the blockSize of cipher algorithm
   */
  CipherTransformation(String name, int algorithmBlockSize) {
    this.name = name;
    this.algorithmBlockSize = algorithmBlockSize;
  }

  /**
   * Gets the algorithm name of cipher.
   *
   * @return name of cipher transformation, as in {@link javax.crypto.Cipher}
   */
  public String getName() {
    return name;
  }

  /**
   * Gets the algorithm block size of cipher.
   *
   * @return size of an algorithm block in bytes.
   */
  public int getAlgorithmBlockSize() {
    return algorithmBlockSize;
  }

  /**
   * Overrides {@link java.lang.Enum#toString()}
   *
   * @return the name of cipher algorithm and blocksize.
   */
  @Override
  public String toString() {
    StringBuilder builder = new StringBuilder("{");
    builder.append("name: " + name);
    builder.append(", algorithmBlockSize: " + algorithmBlockSize);
    builder.append("}");
    return builder.toString();
  }

  /**
   * Converts to CipherTransformation from name, {@link #algorithmBlockSize} 
   * is fixed for certain cipher transformation, just need to compare the name.
   *
   * @param name cipher transformation name
   * @return CipherTransformation cipher transformation
   */
  public static CipherTransformation fromName(String name) {
    CipherTransformation[] transformations = CipherTransformation.values();
    for (CipherTransformation transformation : transformations) {
      if (transformation.getName().equals(name)) {
        return transformation;
      }
    }
    throw new IllegalArgumentException("Invalid transformation name: " + name);
  }
}
