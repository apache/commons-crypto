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
package org.apache.commons.crypto.random;

import java.io.IOException;
import java.util.Arrays;

import org.junit.Test;

public abstract class AbstractRandomTest {

  public abstract SecureRandom getSecureRandom() throws IOException;

  @Test(timeout=120000)
  public void testRandomBytes() throws Exception {
    SecureRandom random = getSecureRandom();
    // len = 16
    checkRandomBytes(random, 16);
    // len = 32
    checkRandomBytes(random, 32);
    // len = 128
    checkRandomBytes(random, 128);
    // len = 256
    checkRandomBytes(random, 256);
    random.close();
  }

  /**
   * Test will timeout if secure random implementation always returns a
   * constant value.
   */
  private void checkRandomBytes(SecureRandom random, int len) {
    byte[] bytes = new byte[len];
    byte[] bytes1 = new byte[len];
    random.nextBytes(bytes);
    random.nextBytes(bytes1);

    while (Arrays.equals(bytes, bytes1)) {
      random.nextBytes(bytes1);
    }
  }
}
