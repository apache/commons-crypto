/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 * <p>
 * http://www.apache.org/licenses/LICENSE-2.0
 * <p>
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.commons.crypto.cipher;

import java.nio.ByteBuffer;

import org.apache.commons.crypto.OpenSslInfo;

/**
 * Delegates calls to a native library for a specific version of OpenSSL.
 */
class OpenSslNativeJni {

    private static final OpenSslNativeImpl nativeImpl;
    private static final long VERSION_3_0_X = 0x30000000;

    static {
        nativeImpl = OpenSslInfo.getOpenSslNativeVersion() >= VERSION_3_0_X ? new OpenSsl3Native() : new OpenSslNative();
    }

    static void _clean(long context) {
        nativeImpl._clean(context);
    }

    static int _ctrl(long context, int type, int arg, byte[] data) {
        return nativeImpl._ctrl(context, type, arg, data);
    }

    static int _doFinal(long context, ByteBuffer output, int offset, int maxOutputLength) {
        return nativeImpl._doFinal(context, output, offset, maxOutputLength);
    }

    static int _doFinalByteArray(long context, byte[] output, int offset, int maxOutputLength) {
        return nativeImpl._doFinalByteArray(context, output, offset, maxOutputLength);
    }

    static long _init(long context, int mode, int alg, int padding, byte[] key, byte[] iv) {
        return nativeImpl._init(context, mode, alg, padding, key, iv);
    }

    static long _initContext(int algorithm, int padding) {
        return nativeImpl._initContext(algorithm, padding);
    }

    static void _initIDs() {
        nativeImpl._initIDs();
    }

    static int _update(long context, ByteBuffer input, int inputOffset, int inputLength, ByteBuffer output, int outputOffset, int maxOutputLength) {
        return nativeImpl._update(context, input, inputOffset, inputLength, output, outputOffset, maxOutputLength);
    }

    static int _updateByteArray(long context, byte[] input, int inputOffset, int inputLength, byte[] output, int outputOffset, int maxOutputLength) {
        return nativeImpl._updateByteArray(context, input, inputOffset, inputLength, output, outputOffset, maxOutputLength);
    }

    static int _updateByteArrayByteBuffer(long context, byte[] input, int inputOffset, int inputLength, ByteBuffer output, int outputOffset,
            int maxOutputLength) {
        return nativeImpl._updateByteArrayByteBuffer(context, input, inputOffset, inputLength, output, outputOffset, maxOutputLength);
    }

}
