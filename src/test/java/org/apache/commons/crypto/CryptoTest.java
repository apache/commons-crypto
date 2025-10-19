/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.commons.crypto;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class CryptoTest {

    // If defined, then fail if the version does not match major/minor bits
    private static final String EXPECTED_VERSION_PROPERTY = "CryptoTest.expectedVersion";

    /**
     * This test may fail unless the code was built by Maven, as it relies on the VERSION file being set up correctly
     */
    @Test
    void testGetComponentName() {
        final String version = Crypto.getComponentName();
        assertNotNull("Should not be null", version);
        assertTrue(version.matches("^Apache Commons Crypto.*"), version);
    }

    /**
     * This test may fail unless the code was built by Maven, as it relies on the VERSION file being set up correctly.
     */
    @Test
    void testGetComponentVersion() {
        final String version = Crypto.getComponentVersion();
        assertNotNull("Should not be null", version);
        assertTrue(version.matches("^\\d+\\.\\d+.*"), version);
    }

    @Test
    void testLoadingError() throws Throwable {
        final Throwable loadingError = Crypto.getLoadingError();
        if (loadingError != null) {
            throw loadingError;
        }
        assertTrue(true, "Completed OK");
    }

    @Test
    void testMain() throws Throwable {
        // Check that Crypto.main will actually run tests
        assertTrue(Crypto.isNativeCodeLoaded(), "Native code loaded OK");
        Crypto.main(new String[] { }); // show the JNI library details
        assertTrue(Crypto.isNativeCodeLoaded(), "Completed OK");
        final String expectedVersion = System.getProperty(EXPECTED_VERSION_PROPERTY, "");
        if (expectedVersion.isEmpty()) {
            System.out.println("OpenSSL version was not checked");
        } else {
            assertEquals(expectedVersion, Long.toHexString(OpenSslInfoNative.OpenSSL() & 0xFFFF0000));
            System.out.println("OpenSSL version is as expected");
        }
    }

}
