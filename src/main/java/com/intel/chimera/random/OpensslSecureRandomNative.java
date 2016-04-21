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
package com.intel.chimera.random;

/**
 * JNI interface of {@link SecureRandom} implementation.
 * The native method in this class is defined in
 * OpensslSecureRandomNative.h(genereted by javah).
 */
public class OpensslSecureRandomNative {

  private OpensslSecureRandomNative() {}

  /**
   * Declares a native method to initialize SR.
   */
  public native static void initSR();

  /**
   * Judges whether use {@link OpensslSecureRandomNative} to
   * generate the user-specified number of random bits.
   *
   * @param bytes the array to be filled in with random bytes.
   * @return true if use {@link OpensslSecureRandomNative} to
   * generate the user-specified number of random bits.
   */
  public native static boolean nextRandBytes(byte[] bytes); 
}
