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

import java.nio.ByteBuffer;

import com.sun.jna.NativeLong;
import com.sun.jna.ptr.PointerByReference;

/**
 * This interface defines the API for the native code.
 * All methods are listed here; individual implementations may not support them all.
 */
interface OpenSslInterfaceNativeJna {

    boolean _INIT_OK();

    Throwable _INIT_ERROR();

    PointerByReference _ENGINE_by_id(final String string);

    int _ENGINE_finish(final PointerByReference rdrandEngine);

    int _ENGINE_free(final PointerByReference rdrandEngine);

    int _ENGINE_init(final PointerByReference rdrandEngine);

    int _ENGINE_set_default(final PointerByReference rdrandEngine, final int flags);

    String _ERR_error_string(final NativeLong err, final char[] buff);

    NativeLong _ERR_peek_error();

    PointerByReference _EVP_aes_128_cbc();

    PointerByReference _EVP_aes_128_ctr();

    PointerByReference _EVP_aes_192_cbc();

    PointerByReference _EVP_aes_192_ctr();

    PointerByReference _EVP_aes_256_cbc();

    PointerByReference _EVP_aes_256_ctr();

    void _EVP_CIPHER_CTX_free(final PointerByReference context);

    PointerByReference _EVP_CIPHER_CTX_new();

    int _EVP_CIPHER_CTX_set_padding(final PointerByReference context, final int padding);

    int _EVP_CipherFinal_ex(final PointerByReference context, final ByteBuffer outBuffer,
            final int[] outlen);

    int _EVP_CipherInit_ex(final PointerByReference context, final PointerByReference algo,
            final PointerByReference impl, final byte[] encoded, final byte[] iv, final int cipherMode);

    int _EVP_CipherUpdate(final PointerByReference context, final ByteBuffer outBuffer,
            final int[] outlen, final ByteBuffer inBuffer, final int remaining);

    int _RAND_bytes(final ByteBuffer buf, final int length);

    PointerByReference _RAND_get_rand_method();

    PointerByReference _RAND_SSLeay();

    String _OpenSSL_version(final int i);

    void _ENGINE_load_rdrand();

    /** TODO Appears to be deprecated as of OpenSSL 1.1.0. */
    int _ENGINE_cleanup();

    void _EVP_CIPHER_CTX_cleanup(final PointerByReference context);
}