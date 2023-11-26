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

    static native boolean dlopen_preflight(String path);

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
        if (dlopen_preflight(path)){
            return null;
        }
        return dlerror();
    }

}
