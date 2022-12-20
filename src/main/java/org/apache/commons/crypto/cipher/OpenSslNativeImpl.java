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

/**
 * JNI interface for native implementations.
 */
interface OpenSslNativeImpl {

    /**
     * Cleans the context at native.
     *
     * @param context The cipher context address
     */
    void _clean(long context);

    /**
     * Allows various cipher specific parameters to be determined and set.
     *
     * it will call OpenSSL's API int EVP_CIPHER_CTX_ctrl(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr) In OpenSSL, data type of ptr can be char* or long*.
     * Here, we map java's byte[] to native void*ptr. Note that the byte order is ByteOrder.nativeOrder.
     *
     * @param context The cipher context address
     * @param type    CtrlValues
     * @param arg     argument like a tag length
     * @param data    byte buffer or null
     * @return return 0 if there is any error, else return 1.
     */
    int _ctrl(long context, int type, int arg, byte[] data);

    /**
     * Finishes a multiple-part operation. The data is encrypted or decrypted, depending on how this cipher was initialized.
     *
     * @param context         The cipher context address
     * @param output          The byte buffer for the result
     * @param offset          The offset in output where the result is stored
     * @param maxOutputLength The maximum length for output
     * @return The number of bytes stored in output
     */
    int _doFinal(long context, ByteBuffer output, int offset, int maxOutputLength);

    /**
     * Finishes a multiple-part operation. The data is encrypted or decrypted, depending on how this cipher was initialized.
     *
     * @param context         The cipher context address
     * @param output          The byte array for the result
     * @param offset          The offset in output where the result is stored
     * @param maxOutputLength The maximum length for output
     * @return The number of bytes stored in output
     */
    int _doFinalByteArray(long context, byte[] output, int offset, int maxOutputLength);

    /**
     * Declares a native method to initialize the cipher context.
     *
     * @param context The cipher context address
     * @param mode    ENCRYPT_MODE or DECRYPT_MODE
     * @param alg     Algorithm Mode of OpenSsl
     * @param padding the padding mode of OpenSsl cipher
     * @param key     crypto key
     * @param iv      crypto iv
     * @return the context address of cipher
     */
    long _init(long context, int mode, int alg, int padding, byte[] key, byte[] iv);

    /**
     * Declares a native method to initialize the cipher context.
     *
     * @param algorithm The algorithm name of cipher
     * @param padding   The padding name of cipher
     * @return the context address of cipher
     */
    long _initContext(int algorithm, int padding);

    /**
     * Declares a native method to initialize JNI field and method IDs.
     */
    void _initIDs();

    /**
     * Continues a multiple-part encryption/decryption operation. The data is encrypted or decrypted, depending on how this cipher was initialized.
     *
     * @param context         The cipher context address
     * @param input           The input byte buffer
     * @param inputOffset     The offset in input where the input starts
     * @param inputLength     The input length
     * @param output          The byte buffer for the result
     * @param outputOffset    The offset in output where the result is stored
     * @param maxOutputLength The maximum length for output
     * @return The number of bytes stored in output
     */
    int _update(long context, ByteBuffer input, int inputOffset, int inputLength, ByteBuffer output, int outputOffset, int maxOutputLength);

    /**
     * Continues a multiple-part encryption/decryption operation. The data is encrypted or decrypted, depending on how this cipher was initialized.
     *
     * @param context         The cipher context address
     * @param input           The input byte array
     * @param inputOffset     The offset in input where the input starts
     * @param inputLength     The input length
     * @param output          The byte array for the result
     * @param outputOffset    The offset in output where the result is stored
     * @param maxOutputLength The maximum length for output
     * @return The number of bytes stored in output
     */
    int _updateByteArray(long context, byte[] input, int inputOffset, int inputLength, byte[] output, int outputOffset, int maxOutputLength);

    /**
     * Continues a multiple-part encryption/decryption operation. The data is encrypted or decrypted, depending on how this cipher was initialized.
     *
     * @param context         The cipher context address
     * @param input           The input byte array
     * @param inputOffset     The offset in input where the input starts
     * @param inputLength     The input length
     * @param output          The byte buffer for the result
     * @param outputOffset    The offset in output where the result is stored
     * @param maxOutputLength The maximum length for output
     * @return The number of bytes stored in output
     */
    int _updateByteArrayByteBuffer(long context, byte[] input, int inputOffset, int inputLength, ByteBuffer output, int outputOffset, int maxOutputLength);

}
