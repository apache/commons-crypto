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

import java.nio.ByteBuffer;

public class OpensslNative {
  public native static void initIDs();

  public native static long initContext(int alg, int padding);

  public native static long init(long context, int mode, int alg, int padding,
      byte[] key, byte[] iv);

  public native static int update(long context, ByteBuffer input,
      int inputOffset, int inputLength, ByteBuffer output, int outputOffset,
      int maxOutputLength);

  public native static int doFinal(long context, ByteBuffer output, int offset,
      int maxOutputLength);

  public native static void clean(long context);
}
