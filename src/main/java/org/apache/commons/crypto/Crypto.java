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

/**
 * The Crypto class provides some diagnostic information about Commons Crypto.
 */
public final class Crypto {

    /**
     * Accessor to the currently active version of Apache Commons Crypto.
     * 
     * @return the version
     */
    public static String getVersion() {
        return NativeCodeLoader.getVersion();
    }

    /**
     * Checks whether the native code has been successfully loaded for the platform.
     * 
     * @return true if the native code has been loaded successful.
     */
    public static boolean isNativeCodeLoaded() {
        return NativeCodeLoader.isNativeCodeLoaded();
    }
}
