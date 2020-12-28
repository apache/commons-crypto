/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */
package org.apache.commons.crypto;


import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class CryptoTest {

	/**
	 * This test may fail unless the code was built by Maven, as it relies on the
	 * VERSION file being set up correctly
	 */
	@Test
	public void testGetComponentName() {
		final String version = Crypto.getComponentName();
		assertNotNull("Should not be null", version);
		assertTrue(version.matches("^Apache Commons Crypto.*"), version);
	}

	/**
	 * This test may fail unless the code was built by Maven, as it relies on the
	 * VERSION file being set up correctly.
	 */
	@Test
	public void testGetComponentVersion() {
		final String version = Crypto.getComponentVersion();
		assertNotNull("Should not be null", version);
		assertTrue(version.matches("^\\d+\\.\\d+.*"), version);
	}

	@Test
	@Disabled("Mac64 failure with OpenSSL 1.1.1g")
	public void testMain() throws Throwable {
		try {
			Crypto.main(new String[0]);
		} catch (final Throwable e) {
			final Throwable loadingError = Crypto.getLoadingError();
			System.err.println("Special case; LoadingError = " + loadingError);
			throw loadingError != null ? loadingError : e;
		}
	}

	@Test
	public void testLoadingError() throws Throwable {
		final Throwable loadingError = Crypto.getLoadingError();
		if (loadingError != null) {
			throw loadingError;
		}
	}

}
