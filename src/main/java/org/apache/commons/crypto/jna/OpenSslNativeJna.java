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

import org.apache.commons.crypto.Crypto;

import com.sun.jna.Function;
import com.sun.jna.NativeLibrary;
import com.sun.jna.NativeLong;
import com.sun.jna.ptr.PointerByReference;

final class OpenSslNativeJna {

    static final int OPENSSL_INIT_ENGINE_RDRAND = 0x00000200;

    static final int OOSL_JNA_ENCRYPT_MODE = 1;
    static final int OOSL_JNA_DECRYPT_MODE = 0;

    static final boolean INIT_OK;

    static final Throwable INIT_ERROR;

    public static final long VERSION;
    public static final long VERSION_1_0_X = 0x10000000;
    public static final long VERSION_1_1_X = 0x10100000;
    public static final long VERSION_2_0_X = 0x20000000;

    private static final OpenSslInterfaceNativeJna JnaImplementation;

    static {
        final String libraryName = System.getProperty(Crypto.CONF_PREFIX + OpenSslNativeJna.class.getSimpleName(), "crypto");
        OpenSslJna.debug("NativeLibrary.getInstance('%s')%n", libraryName);
        final NativeLibrary crypto = NativeLibrary.getInstance(libraryName);
        Function version = null;
        try {
            version = crypto.getFunction("SSLeay");
        } catch (final UnsatisfiedLinkError e) {
            version = crypto.getFunction("OpenSSL_version_num");
        }
        // Must find one of the above two functions; else give up

        VERSION = version.invokeLong(new Object[]{}) & 0xffff0000; // keep only major.minor
        if (VERSION == VERSION_1_0_X) {
           JnaImplementation = new OpenSsl10XNativeJna();
        } else if (VERSION == VERSION_1_1_X) {
            JnaImplementation = new OpenSsl11XNativeJna();
        } else if (VERSION == VERSION_2_0_X) {
            JnaImplementation = new OpenSsl20XNativeJna();
        } else {
            // TODO: Throw error?
            JnaImplementation = new OpenSsl10XNativeJna();
        }

        OpenSslJna.debug(String.format("Detected version 0x%x", VERSION));

        INIT_OK = JnaImplementation._INIT_OK();

        INIT_ERROR = INIT_OK ? null : JnaImplementation._INIT_ERROR();
    }

    private OpenSslNativeJna() {
    }

    public static PointerByReference ENGINE_by_id(final String string) {
        return JnaImplementation._ENGINE_by_id(string);
    }

    public static int ENGINE_finish(final PointerByReference rdrandEngine) {
        return JnaImplementation._ENGINE_finish(rdrandEngine);
    }

    public static int ENGINE_free(final PointerByReference rdrandEngine) {
        return JnaImplementation._ENGINE_free(rdrandEngine);
    }

    public static int ENGINE_init(final PointerByReference rdrandEngine) {
        return JnaImplementation._ENGINE_init(rdrandEngine);
    }

    public static int ENGINE_set_default(final PointerByReference rdrandEngine, final int eNGINE_METHOD_RAND) {
        return JnaImplementation._ENGINE_set_default(rdrandEngine, eNGINE_METHOD_RAND);
    }

    public static String ERR_error_string(final NativeLong err, final char[] object) {
        return JnaImplementation._ERR_error_string(err, null);
    }

    public static NativeLong ERR_peek_error() {
        return JnaImplementation._ERR_peek_error();
    }

    public static PointerByReference EVP_aes_128_cbc() {
        return JnaImplementation._EVP_aes_128_cbc();
    }

    public static PointerByReference EVP_aes_128_ctr() {
        return JnaImplementation._EVP_aes_128_ctr();
    }

    public static PointerByReference EVP_aes_192_cbc() {
        return JnaImplementation._EVP_aes_192_cbc();
    }

    public static PointerByReference EVP_aes_192_ctr() {
        return JnaImplementation._EVP_aes_192_ctr();
    }

    public static PointerByReference EVP_aes_256_cbc() {
        return JnaImplementation._EVP_aes_256_cbc();
    }

    public static PointerByReference EVP_aes_256_ctr() {
        return JnaImplementation._EVP_aes_256_ctr();
    }

    public static void EVP_CIPHER_CTX_free(final PointerByReference context) {
        JnaImplementation._EVP_CIPHER_CTX_free(context);
    }

    public static PointerByReference EVP_CIPHER_CTX_new() {
        return JnaImplementation._EVP_CIPHER_CTX_new();
    }

    public static int EVP_CIPHER_CTX_set_padding(final PointerByReference context, final int padding) {
        return JnaImplementation._EVP_CIPHER_CTX_set_padding(context, padding);
    }

    public static int EVP_CipherFinal_ex(final PointerByReference context, final ByteBuffer outBuffer,
            final int[] outlen) {
        return JnaImplementation._EVP_CipherFinal_ex(context, outBuffer, outlen);
    }

    // TODO: native method expects PointerByReference implementation
    public static int EVP_CipherInit_ex(final PointerByReference context, final PointerByReference algo,
            final Object object, final byte[] encoded, final byte[] iv, final int cipherMode) {
        return JnaImplementation._EVP_CipherInit_ex(context, algo, null, encoded, iv, cipherMode);
    }

    public static int EVP_CipherUpdate(final PointerByReference context, final ByteBuffer outBuffer,
            final int[] outlen, final ByteBuffer inBuffer, final int remaining) {
        return JnaImplementation._EVP_CipherUpdate(context, outBuffer, outlen, inBuffer, remaining);
    }

    public static int RAND_bytes(final ByteBuffer buf, final int length) {
        return JnaImplementation._RAND_bytes(buf, length);
    }

    public static PointerByReference RAND_get_rand_method() {
        return JnaImplementation._RAND_get_rand_method();
    }

    public static PointerByReference RAND_SSLeay() {
        return JnaImplementation._RAND_SSLeay();
    }

    public static String OpenSSLVersion(final int i) {
        return JnaImplementation._OpenSSL_version(i);
    }

    public static void ENGINE_load_rdrand() {
        JnaImplementation._ENGINE_load_rdrand();
    }

    public static int ENGINE_cleanup() {
        return JnaImplementation._ENGINE_cleanup();
    }

    public static void EVP_CIPHER_CTX_cleanup(final PointerByReference context) {
        JnaImplementation._EVP_CIPHER_CTX_cleanup(context);
    }
}