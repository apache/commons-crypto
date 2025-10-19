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
package org.apache.commons.crypto.jna;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

class OpenSslJnaTest {

    // If defined, then fail if the version does not match major/minor bits
    private static final String EXPECTED_VERSION_PROPERTY = "OpenSslJnaTest.expectedVersion";

    @Test
    void testMain() throws Throwable {
        OpenSslJna.main(new String[0]);
        final String expectedVersion = System.getProperty(EXPECTED_VERSION_PROPERTY, "");
        if (expectedVersion.isEmpty()) {
            System.out.println("OpenSSL version was not checked");
        } else {
            assertEquals(expectedVersion, Long.toHexString(OpenSslNativeJna.OpenSSL_version_num() & 0xFFFF0000));
            System.out.println("OpenSSL version is as expected");
        }
   }
}
