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

package org.apache.commons.crypto.jna;

import com.sun.jna.Native;

/*
 * Get access to dlopen_preflight from JNA code
 * For use on macOS only - CRYPTO-179
 */
class OpenSslMacOS {

    /*
     * The method is declared as 'bool dlopen_preflight(const char* path)', which is not a standard
     * JNA type, see:
     * http://java-native-access.github.io/jna/5.13.0/javadoc/overview-summary.html#marshalling
     * bool appears to be closest to a byte, where non-zero is true and zero is false
     */
    static native byte dlopen_preflight(String path);

    static native String dlerror();

    static {
        Native.register((String)null);
    }

    /**
     * Check if can load library OK
     * @param path
     * @return null if OK, else error message
     */
    public static String checkLibrary(String path) {
        boolean loadedOK = dlopen_preflight(path) != 0;
        String dlerror = dlerror(); // fetch error, and clear for next call
        return  loadedOK ? null : dlerror;
    }

}
