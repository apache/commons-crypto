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

    /** Full version from JNA call. */
    static final long VERSION;

    /** Major Minor version from JNA call, without the maintenance level. */
    static final long VERSION_X_Y;

    static final long VERSION_1_1_X = 0x10100000;
    static final long VERSION_2_0_X = 0x20000000;
    static final long VERSION_3_0_X = 0x30000000;
    static final long VERSION_3_1_X = 0x30100000;

    private static final OpenSslInterfaceNativeJna JnaImplementation;

    static {
        OpenSslJna.debug("OpenSslNativeJna static init start");
        final String libraryName = System.getProperty(Crypto.JNA_LIBRARY_NAME, Crypto.JNA_LIBRARY_NAME_DEFAULT);
        OpenSslJna.debug("OpenSslNativeJna NativeLibrary.getInstance('%s')", libraryName);
        // CRYPTO-179 - avoid crash
        if ("Mac OS X".equals(System.getProperty("os.name"))
            && System.getProperty(Crypto.JNA_LIBRARY_NAME, "").isEmpty()
            && System.getProperty(Crypto.JNA_LIBRARY_PATH, "").isEmpty()
        ) {
            String ret = OpenSslMacOS.checkLibrary(Crypto.MACOS_LIBRARY_NAME_DEFAULT);
            if (ret != null) {
                throw new UnsatisfiedLinkError(
                    String.format("Cannot load default library '%s'; need jni.library.path! (%s)",
                        Crypto.MACOS_LIBRARY_NAME_DEFAULT, ret));
            }
        }
            System.err.println("Lib check4" );
        @SuppressWarnings("resource") // NativeLibrary.getInstance returns a singleton
        final NativeLibrary crypto = NativeLibrary.getInstance(libraryName);
        OpenSslJna.debug("OpenSslNativeJna NativeLibrary.getInstance('%s') -> %s", libraryName, crypto);
        Function versionFunction = null;
        try {
            versionFunction = crypto.getFunction("SSLeay"); // Needed for LibreSSL 2.x
        } catch (final UnsatisfiedLinkError e) {
            versionFunction = crypto.getFunction("OpenSSL_version_num");
        }
        // Must find one of the above two functions; else give up

        VERSION = versionFunction.invokeLong(new Object[]{});
        //CHECKSTYLE:OFF
        VERSION_X_Y = VERSION & 0xffff0000; // keep only major.minor checkstyle:
        //CHECKSTYLE:ON

        OpenSslJna.debug(String.format("OpenSslNativeJna detected version 0x%x => 0x%x", VERSION, VERSION_X_Y));

        if (VERSION_X_Y == VERSION_1_1_X) {
            OpenSslJna.debug("Creating OpenSsl11XNativeJna");
            JnaImplementation = new OpenSsl11XNativeJna();
        } else if (VERSION_X_Y == VERSION_2_0_X) {
            OpenSslJna.debug("Creating LibreSsl20XNativeJna");
            JnaImplementation = new LibreSsl20XNativeJna();
       } else if (VERSION_X_Y == VERSION_3_0_X || VERSION_X_Y == VERSION_3_1_X) { // assume these are the same
           OpenSslJna.debug("Creating OpenSsl30XNativeJna");
           JnaImplementation = new OpenSsl30XNativeJna();
       } else {
            throw new UnsupportedOperationException(String.format("Unsupported Version: %x", VERSION_X_Y));
       }

        INIT_OK = JnaImplementation._INIT_OK();

        INIT_ERROR = INIT_OK ? null : JnaImplementation._INIT_ERROR();
        OpenSslJna.debug("OpenSslNativeJna INIT_OK = %s, INIT_ERROR = '%s', JnaImplementation = %s", INIT_OK, INIT_ERROR, JnaImplementation.getClass());
        OpenSslJna.debug("OpenSslNativeJna static init end");
    }

    public static PointerByReference ENGINE_by_id(final String string) {
        return JnaImplementation._ENGINE_by_id(string);
    }

    public static int ENGINE_cleanup() {
        return JnaImplementation._ENGINE_cleanup();
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

    public static void ENGINE_load_rdrand() {
        JnaImplementation._ENGINE_load_rdrand();
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

    public static void EVP_CIPHER_CTX_cleanup(final PointerByReference context) {
        JnaImplementation._EVP_CIPHER_CTX_cleanup(context);
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

    public static int EVP_CipherInit_ex(final PointerByReference context, final PointerByReference algo,
            final Object object, final byte[] encoded, final byte[] iv, final int cipherMode) {
        return JnaImplementation._EVP_CipherInit_ex(context, algo, null, encoded, iv, cipherMode);
    }

    public static int EVP_CipherUpdate(final PointerByReference context, final ByteBuffer outBuffer,
            final int[] outlen, final ByteBuffer inBuffer, final int remaining) {
        return JnaImplementation._EVP_CipherUpdate(context, outBuffer, outlen, inBuffer, remaining);
    }

    public static String OpenSSLVersion(final int i) {
        return JnaImplementation._OpenSSL_version(i);
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

    private OpenSslNativeJna() {
    }
}
