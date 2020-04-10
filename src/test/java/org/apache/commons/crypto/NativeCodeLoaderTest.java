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

package org.apache.commons.crypto;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.io.File;

import org.junit.Assume;
import org.junit.Ignore;
import org.junit.Test;

public class NativeCodeLoaderTest {

    @Test
    public void test() {
        if (NativeCodeLoader.isNativeCodeLoaded()) {
            // TODO display versions once available
            System.out.println("** INFO: Native (JNI) code loaded successfully");
        } else {
            System.out.println("** WARN: Native (JNI) code was not loaded: "
                + NativeCodeLoader.getLoadingError());
        }
    }

    @Test
    public void testNativePresent() {
        Assume.assumeTrue(NativeCodeLoader.isNativeCodeLoaded());
        assertNull(NativeCodeLoader.getLoadingError());
    }

    @Test
    public void testNativeNotPresent() {
        Assume.assumeTrue(!NativeCodeLoader.isNativeCodeLoaded());
        assertNotNull(NativeCodeLoader.getLoadingError());
    }

    @Test
    public void testCanLoadIfPresent() {
        Assume.assumeTrue(NativeCodeLoader.isNativeCodeLoaded());
        // This will try to reload the library, so should work
        assertNull(NativeCodeLoader.loadLibrary());
    }

    @Test
    @Ignore("Seems to cause issues with other tests on Linux; disable for now")
    public void testUnSuccessfulLoad() throws Exception {
        final String nameKey = System.getProperty(Crypto.LIB_NAME_KEY);
        final String pathKey = System.getProperty(Crypto.LIB_PATH_KEY);
        // An empty file should cause UnsatisfiedLinkError
        final File empty = File.createTempFile("NativeCodeLoaderTest", "tmp");
        try {
            System.setProperty(Crypto.LIB_PATH_KEY, empty.getParent());
            System.setProperty(Crypto.LIB_NAME_KEY, empty.getName());
            final Throwable result = NativeCodeLoader.loadLibrary();
            assertNotNull(result);
            assertTrue(result instanceof UnsatisfiedLinkError);
        } finally {
            empty.delete();
            if (nameKey != null) {
                System.setProperty(Crypto.LIB_NAME_KEY, nameKey);
            }
            if (pathKey != null) {
                System.setProperty(Crypto.LIB_PATH_KEY, pathKey);
            }
        }
    }
}
