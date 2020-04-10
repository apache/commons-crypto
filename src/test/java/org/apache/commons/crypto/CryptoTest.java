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

import org.junit.Assert;
import org.junit.Test;

public class CryptoTest {

    @Test
    // This test may fail unless the code was built by Maven, as
    // it relies on the VERSION file being set up correctly
    public void testGetComponentVersion() {
        final String version = Crypto.getComponentVersion();
        Assert.assertNotNull("Should not be null",version);
        Assert.assertTrue(version,version.matches("^\\d+\\.\\d+.*"));
    }

    @Test
    // This test may fail unless the code was built by Maven, as
    // it relies on the VERSION file being set up correctly
    public void testGetComponentName() {
        final String version = Crypto.getComponentName();
        Assert.assertNotNull("Should not be null",version);
        Assert.assertTrue(version,version.matches("^Apache Commons Crypto.*"));
    }

}
