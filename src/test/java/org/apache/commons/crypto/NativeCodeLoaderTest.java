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

package org.apache.commons.crypto;

import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.nio.file.Files;
import java.nio.file.Path;

import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

public class NativeCodeLoaderTest {

    @Test
    public void test() {
        assertTrue(NativeCodeLoader.isNativeCodeLoaded(), "Native (JNI) code loaded successfully");
    }

    @Test
    @Disabled("Causes crash on Ubuntu when compiled with Java 17")
    // Also failed on:
    // macos-11:java 11,17,21
    // ubuntu-20.04:java 17,21 (11 was OK)
    // windows-latest:java 17 (11,21 OK)
    // The following error is reported:
    // "Corrupted channel by directly writing to native stream in forked JVM 1"
    // Note that this appears during a subsequent test, and does not
    // happen every time.
    // At this point it is not known where the native stream is written.
    public void testCanLoadIfPresent() {
        assumeTrue(NativeCodeLoader.isNativeCodeLoaded());
        // This will try to reload the library, so should work
        assertNull(NativeCodeLoader.loadLibrary());
    }

    @Test
    public void testNativeNotPresent() {
        assumeTrue(!NativeCodeLoader.isNativeCodeLoaded());
        assertNotNull(NativeCodeLoader.getLoadingError());
    }

    @Test
    public void testNativePresent() {
        assumeTrue(NativeCodeLoader.isNativeCodeLoaded());
        assertNull(NativeCodeLoader.getLoadingError());
    }

    @Test
    @Disabled("Seems to cause issues with other tests on Linux; disable for now")
    // It causes problems because the system properties are temporarily changed.
    // However, properties are only fetched once, thus the test either corrupts the settings
    // or does not work, depending on the order of tests.
    public void testUnSuccessfulLoad() throws Exception {
        final String nameKey = System.getProperty(Crypto.LIB_NAME_KEY);
        final String pathKey = System.getProperty(Crypto.LIB_PATH_KEY);
        // An empty file should cause UnsatisfiedLinkError
        final Path empty = Files.createTempFile("NativeCodeLoaderTest", "tmp");
        try {
            System.setProperty(Crypto.LIB_PATH_KEY, empty.getParent().toString());
            System.setProperty(Crypto.LIB_NAME_KEY, empty.getFileName().toString());
            final Throwable result = NativeCodeLoader.loadLibrary();
            assertNotNull(result);
            assertInstanceOf(UnsatisfiedLinkError.class, result);
        } finally {
            Files.delete(empty);
            if (nameKey != null) {
                System.setProperty(Crypto.LIB_NAME_KEY, nameKey);
            }
            if (pathKey != null) {
                System.setProperty(Crypto.LIB_PATH_KEY, pathKey);
            }
        }
    }
}
