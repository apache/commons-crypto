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

/**
 * Provides OpenSSL information.
 *
 * @since 1.2.0
 */
public final class OpenSslInfo {

    private static final long VERSION_3_0_X = 0x30000000;

    /**
     * Gets the OpenSSL version.
     *
     * @return the OpenSSL version.
     */
    public static long getOpenSslNativeVersion() {
        return OpenSslInfoNative.OpenSSL();
    }

	/**
     * Tests if the OpenSSL version is 3 or above.
     *
     * @return true if the OpenSSL version is 3 or above.
     */
	public static boolean isOpenSslNativeVersion3() {
		return getOpenSslNativeVersion() >= OpenSslInfo.VERSION_3_0_X;
	}
}
