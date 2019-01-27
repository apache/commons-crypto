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

package org.apache.commons.crypto.jna;

import java.nio.ByteBuffer;

import com.sun.jna.Function;
import com.sun.jna.NativeLibrary;
import com.sun.jna.NativeLong;
import com.sun.jna.ptr.PointerByReference;

class OpenSslNativeJna {

    static final int OPENSSL_INIT_ENGINE_RDRAND = 0x00000200;

    static final int OOSL_JNA_ENCRYPT_MODE = 1;
    static final int OOSL_JNA_DECRYPT_MODE = 0;

    static final boolean INIT_OK;

    static final Throwable INIT_ERROR;

    public static final long VERSION;
    public static final long VERSION_1_0_X = 0x10000000;
    public static final long VERSION_1_1_X = 0x10100000;

    static {
        NativeLibrary crypto = NativeLibrary.getInstance("crypto");
        Function version = null;
        try {
            version = crypto.getFunction("SSLeay");
        } catch (UnsatisfiedLinkError e) {
            // Swallow the Error.
        }

        if (version == null) {
            VERSION = VERSION_1_1_X;
        } else {
            VERSION = VERSION_1_0_X;
        }

        if (VERSION == VERSION_1_1_X) {
            INIT_OK = OpenSsl11XNativeJna.INIT_OK;
        } else {
            INIT_OK = OpenSsl10XNativeJna.INIT_OK;
        }

        if (INIT_OK) {
            INIT_ERROR = null;
        } else if (VERSION == VERSION_1_1_X) {
            INIT_ERROR = OpenSsl11XNativeJna.INIT_ERROR;
        } else {
            INIT_ERROR = OpenSsl10XNativeJna.INIT_ERROR;
        }
    }

    public static PointerByReference ENGINE_by_id(String string) {
        if (VERSION == VERSION_1_1_X) {
            return OpenSsl11XNativeJna.ENGINE_by_id(string);
        } else {
            return OpenSsl10XNativeJna.ENGINE_by_id(string);
        }
    }

    public static void ENGINE_finish(PointerByReference rdrandEngine) {
        if (VERSION == VERSION_1_1_X) {
            OpenSsl11XNativeJna.ENGINE_finish(rdrandEngine);
        } else {
            OpenSsl10XNativeJna.ENGINE_finish(rdrandEngine);
        }
    }

    public static void ENGINE_free(PointerByReference rdrandEngine) {
        if (VERSION == VERSION_1_1_X) {
            OpenSsl11XNativeJna.ENGINE_free(rdrandEngine);
        } else {
            OpenSsl10XNativeJna.ENGINE_free(rdrandEngine);
        }
    }

    public static int ENGINE_init(PointerByReference rdrandEngine) {
        if (VERSION == VERSION_1_1_X) {
            return OpenSsl11XNativeJna.ENGINE_init(rdrandEngine);
        } else {
            return OpenSsl10XNativeJna.ENGINE_init(rdrandEngine);
        }
    }

    public static int ENGINE_set_default(PointerByReference rdrandEngine, int eNGINE_METHOD_RAND) {
        if (VERSION == VERSION_1_1_X) {
            return OpenSsl11XNativeJna.ENGINE_set_default(rdrandEngine, eNGINE_METHOD_RAND);
        } else {
            return OpenSsl10XNativeJna.ENGINE_set_default(rdrandEngine, eNGINE_METHOD_RAND);
        }
    }

    public static String ERR_error_string(NativeLong err, Object object) {
        if (VERSION == VERSION_1_1_X) {
            return OpenSsl11XNativeJna.ERR_error_string(err, null);
        } else {
            return OpenSsl10XNativeJna.ERR_error_string(err, null);
        }
    }

    public static NativeLong ERR_peek_error() {
        if (VERSION == VERSION_1_1_X) {
            return OpenSsl11XNativeJna.ERR_peek_error();
        } else {
            return OpenSsl10XNativeJna.ERR_peek_error();
        }
    }

    public static PointerByReference EVP_aes_128_cbc() {
        if (VERSION == VERSION_1_1_X) {
            return OpenSsl11XNativeJna.EVP_aes_128_cbc();
        } else {
            return OpenSsl10XNativeJna.EVP_aes_128_cbc();
        }
    }

    public static PointerByReference EVP_aes_128_ctr() {
        if (VERSION == VERSION_1_1_X) {
            return OpenSsl11XNativeJna.EVP_aes_128_ctr();
        } else {
            return OpenSsl10XNativeJna.EVP_aes_128_ctr();
        }
    }

    public static PointerByReference EVP_aes_192_cbc() {
        if (VERSION == VERSION_1_1_X) {
            return OpenSsl11XNativeJna.EVP_aes_192_cbc();
        } else {
            return OpenSsl10XNativeJna.EVP_aes_192_cbc();
        }
    }

    public static PointerByReference EVP_aes_192_ctr() {
        if (VERSION == VERSION_1_1_X) {
            return OpenSsl11XNativeJna.EVP_aes_192_ctr();
        } else {
            return OpenSsl10XNativeJna.EVP_aes_192_ctr();
        }
    }

    public static PointerByReference EVP_aes_256_cbc() {
        if (VERSION == VERSION_1_1_X) {
            return OpenSsl11XNativeJna.EVP_aes_256_cbc();
        } else {
            return OpenSsl10XNativeJna.EVP_aes_256_cbc();
        }
    }

    public static PointerByReference EVP_aes_256_ctr() {
        if (VERSION == VERSION_1_1_X) {
            return OpenSsl11XNativeJna.EVP_aes_256_ctr();
        } else {
            return OpenSsl10XNativeJna.EVP_aes_256_ctr();
        }
    }

    public static void EVP_CIPHER_CTX_free(PointerByReference context) {
        if (VERSION == VERSION_1_1_X) {
            OpenSsl11XNativeJna.EVP_CIPHER_CTX_free(context);
        } else {
            OpenSsl10XNativeJna.EVP_CIPHER_CTX_free(context);
        }
    }

    public static PointerByReference EVP_CIPHER_CTX_new() {
        if (VERSION == VERSION_1_1_X) {
            return OpenSsl11XNativeJna.EVP_CIPHER_CTX_new();
        } else {
            return OpenSsl10XNativeJna.EVP_CIPHER_CTX_new();
        }
    }

    public static void EVP_CIPHER_CTX_set_padding(PointerByReference context, int padding) {
        if (VERSION == VERSION_1_1_X) {
            OpenSsl11XNativeJna.EVP_CIPHER_CTX_set_padding(context, padding);
        } else {
            OpenSsl10XNativeJna.EVP_CIPHER_CTX_set_padding(context, padding);
        }
    }

    public static int EVP_CipherFinal_ex(PointerByReference context, ByteBuffer outBuffer,
            int[] outlen) {
        if (VERSION == VERSION_1_1_X) {
            return OpenSsl11XNativeJna.EVP_CipherFinal_ex(context, outBuffer, outlen);
        } else {
            return OpenSsl10XNativeJna.EVP_CipherFinal_ex(context, outBuffer, outlen);
        }
    }

    public static int EVP_CipherInit_ex(PointerByReference context, PointerByReference algo,
            Object object, byte[] encoded, byte[] iv, int cipherMode) {
        if (VERSION == VERSION_1_1_X) {
            return OpenSsl11XNativeJna.EVP_CipherInit_ex(context, algo, null, encoded, iv,
                    cipherMode);
        } else {
            return OpenSsl10XNativeJna.EVP_CipherInit_ex(context, algo, null, encoded, iv,
                    cipherMode);
        }
    }

    public static int EVP_CipherUpdate(PointerByReference context, ByteBuffer outBuffer,
            int[] outlen, ByteBuffer inBuffer, int remaining) {
        if (VERSION == VERSION_1_1_X) {
            return OpenSsl11XNativeJna.EVP_CipherUpdate(context, outBuffer, outlen, inBuffer,
                    remaining);
        } else {
            return OpenSsl10XNativeJna.EVP_CipherUpdate(context, outBuffer, outlen, inBuffer,
                    remaining);
        }
    }

    public static int RAND_bytes(ByteBuffer buf, int length) {
        if (VERSION == VERSION_1_1_X) {
            return OpenSsl11XNativeJna.RAND_bytes(buf, length);
        } else {
            return OpenSsl10XNativeJna.RAND_bytes(buf, length);
        }
    }

    public static PointerByReference RAND_get_rand_method() {
        if (VERSION == VERSION_1_1_X) {
            return OpenSsl11XNativeJna.RAND_get_rand_method();
        } else {
            return OpenSsl10XNativeJna.RAND_get_rand_method();
        }
    }

    public static PointerByReference RAND_SSLeay() {
        if (VERSION == VERSION_1_1_X) {
            return null;
        } else {
            return OpenSsl10XNativeJna.RAND_SSLeay();
        }
    }

    public static String OpenSSLVersion(int i) {
        if (VERSION == VERSION_1_1_X) {
            return OpenSsl11XNativeJna.OpenSSL_version(i);
        } else {
            return OpenSsl10XNativeJna.SSLeay_version(i);
        }
    }

    public static void ENGINE_load_rdrand() {
        if (VERSION == VERSION_1_1_X) {
            return;
        } else {
            OpenSsl10XNativeJna.ENGINE_load_rdrand();
        }
    }

    public static void ENGINE_cleanup() {
        if (VERSION == VERSION_1_1_X) {
            return;
        } else {
            OpenSsl10XNativeJna.ENGINE_cleanup();
        }
    }

    public static void EVP_CIPHER_CTX_cleanup(PointerByReference context) {
        if (VERSION == VERSION_1_1_X) {
            return;
        } else {
            OpenSsl10XNativeJna.EVP_CIPHER_CTX_cleanup(context);
        }
    }
}