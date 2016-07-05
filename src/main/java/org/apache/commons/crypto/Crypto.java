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
 * Provides diagnostic information about Commons Crypto and keys for native class loading
 */
public final class Crypto {

    /**
     * The prefix of all crypto configuration keys
     */
    public static final String CONF_PREFIX = "commons.crypto.";

    // native lib related configuration keys
    /**
     * The configuration key of the path for loading crypto library.
     */
    public static final String LIB_PATH_KEY = Crypto.CONF_PREFIX
            + "lib.path";
    /**
     * The configuration key of the file name for loading crypto library.
     */
    public static final String LIB_NAME_KEY = Crypto.CONF_PREFIX
            + "lib.name";
    /**
     * The configuration key of temp directory for extracting crypto library.
     * Defaults to "java.io.tempdir" if not found.
     */
    public static final String LIB_TEMPDIR_KEY = Crypto.CONF_PREFIX
            + "lib.tempdir";

    /**
     * Gets the currently active version of Apache Commons Crypto.
     * 
     * @return the version
     */
    public static String getVersion() {
        return NativeCodeLoader.getVersion();
    }

    /**
     * Checks whether the native code has been successfully loaded for the platform.
     * 
     * @return true if the native code has been loaded successfully.
     */
    public static boolean isNativeCodeLoaded() {
        return NativeCodeLoader.isNativeCodeLoaded();
    }

}
