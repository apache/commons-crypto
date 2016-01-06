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
package com.intel.chimera.crypto;

/**
 * Defines properties of a CipherTransformation. Modeled after the ciphers in
 * {@link javax.crypto.Cipher}.
 */
public enum CipherTransformation {
  UNKNOWN("Unknown", 0),
  AES_CTR_NOPADDING("AES/CTR/NoPadding", 16);

  private final String name;
  private final int algorithmBlockSize;

  CipherTransformation(String name, int algorithmBlockSize) {
    this.name = name;
    this.algorithmBlockSize = algorithmBlockSize;
  }

  /**
   * @return name of cipher transformation, as in {@link javax.crypto.Cipher}
   */
  public String getName() {
    return name;
  }

  /**
   * @return size of an algorithm block in bytes
   */
  public int getAlgorithmBlockSize() {
    return algorithmBlockSize;
  }

  @Override
  public String toString() {
    StringBuilder builder = new StringBuilder("{");
    builder.append("name: " + name);
    builder.append(", algorithmBlockSize: " + algorithmBlockSize);
    builder.append("}");
    return builder.toString();
  }

  /**
   * Convert to CipherTransformation from name, {@link #algorithmBlockSize} is fixed
   * for certain cipher transformation, just need to compare the name.
   *
   * @param name cipher transformation name
   * @return CipherTransformation cipher transformation
   */
  public static CipherTransformation convert(String name) {
    CipherTransformation[] transformations = CipherTransformation.values();
    for (CipherTransformation transformation : transformations) {
      if (transformation.getName().equals(name)) {
        return transformation;
      }
    }
    throw new IllegalArgumentException("Invalid transformation name: " + name);
  }

  /**
   * Returns suffix of cipher transformation configuration.
   * @return String configuration suffix
   */
  public static String getConfigSuffix(String name) {
    String[] parts = name.split("/");
    StringBuilder suffix = new StringBuilder();
    for (String part : parts) {
      suffix.append(".").append(part.toLowerCase());
    }

    return suffix.toString();
  }
}
