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

/**
 * This enum is defined for OpensslNative.ctrl() to allow various cipher
 * specific parameters to be determined and set.
 * see the macro definitions in openssl/evp.h
 */
enum OpenSslEvpCtrlValues {
    INIT(0x00),
    SET_KEY_LENGTH(0x01),
    GET_RC2_KEY_BITS(0x02),
    SET_RC2_KEY_BITS(0x03),
    GET_RC5_ROUNDS(0x04),
    SET_RC5_ROUNDS(0x05),
    RAND_KEY(0x06),
    PBE_PRF_NID(0x07),
    COPY(0x08),
    AEAD_SET_IVLEN(0x09),
    AEAD_GET_TAG(0x10),
    AEAD_SET_TAG(0x11),
    AEAD_SET_IV_FIXED(0x12),
    GCM_IV_GEN(0x13),
    CCM_SET_L(0x14),
    CCM_SET_MSGLEN(0x15);

    private final int value;

    OpenSslEvpCtrlValues(int value) {
        this.value = value;
    }

    public int getValue() {
        return value;
    }
}
