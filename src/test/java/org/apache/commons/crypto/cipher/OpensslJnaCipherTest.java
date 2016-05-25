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

package org.apache.commons.crypto.cipher;

import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;

import org.apache.commons.crypto.jna.OpensslJnaCipher;
import org.junit.Assert;
import org.junit.Assume;
import org.junit.Test;

public class OpensslJnaCipherTest extends AbstractCipherTest {

    @Override
    public void init() {
        transformations = new CipherTransformation[] {
                CipherTransformation.AES_CBC_NOPADDING,
                CipherTransformation.AES_CBC_PKCS5PADDING,
                CipherTransformation.AES_CTR_NOPADDING
                };
        cipherClass = OpensslJnaCipher.class.getName();
    }
}
