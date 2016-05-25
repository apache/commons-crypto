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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import com.sun.jna.Native;
import com.sun.jna.NativeLong;
import com.sun.jna.ptr.PointerByReference;

public class OpensslNativeJna {

    private static final Log LOG = LogFactory.getLog(OpensslNativeJna.class
            .getName());
    static final int OPENSSL_INIT_ENGINE_RDRAND = 0x00000200;

    static final int OOSL_JNA_ENCRYPT_MODE = 1;
    static final int OOSL_JNA_DECRYPT_MODE = 0;

    static {
        Native.register("crypto");
        ERR_load_crypto_strings();
        LOG.debug(SSLeay_version(0)+", protected mode supported: "+Native.isProtected());
    }

    //misc
    public static native NativeLong SSLeay();
    public static native String SSLeay_version(int type);
    public static native void ERR_load_crypto_strings();
    public static native NativeLong ERR_peek_error();
    public static native String ERR_error_string(NativeLong err, char[] null_);
    //String ERR_lib_error_string(NativeLong err);
    //String ERR_func_error_string(NativeLong err);
    //String ERR_reason_error_string(NativeLong err);
    
    //en-/decryption
    public static native PointerByReference EVP_CIPHER_CTX_new();
    public static native void EVP_CIPHER_CTX_init(PointerByReference p);
    public static native int EVP_CIPHER_CTX_set_padding(PointerByReference c, int pad);
    public static native PointerByReference EVP_aes_128_cbc();
    public static native PointerByReference EVP_aes_128_ctr();
    public static native PointerByReference EVP_aes_192_cbc();
    public static native PointerByReference EVP_aes_192_ctr();
    public static native PointerByReference EVP_aes_256_cbc();
    public static native PointerByReference EVP_aes_256_ctr();
    public static native int EVP_CipherInit_ex(PointerByReference ctx, PointerByReference cipher, PointerByReference impl, byte key[], byte iv[], int enc);
    public static native int EVP_CipherUpdate(PointerByReference ctx, ByteBuffer bout, int[] outl, ByteBuffer in, int inl);
    public static native int EVP_CipherFinal_ex(PointerByReference ctx, ByteBuffer bout, int[] outl);   
    public static native void EVP_CIPHER_CTX_free(PointerByReference c);
    public static native void EVP_CIPHER_CTX_cleanup(PointerByReference c);
    
    //Random generator
    public static native PointerByReference RAND_get_rand_method();
    public static native PointerByReference RAND_SSLeay();
    public static native int RAND_bytes(ByteBuffer buf, int num);
    public static native int ENGINE_finish(PointerByReference e);
    public static native int ENGINE_free(PointerByReference e);
    public static native int ENGINE_cleanup();
    public static native int ENGINE_init(PointerByReference e);
    public static native int ENGINE_set_default(PointerByReference e, int flags);
    public static native PointerByReference ENGINE_by_id(String id);
    public static native void ENGINE_load_rdrand();
    
    //TODO callback multithreading
    /*public interface Id_function_cb extends Callback {
        long invoke ();
    }
   
    public interface Locking_function_cb extends Callback {
        void invoke(int mode, int n, String file, int line);
    }
    
    public static final Id_function_cb default_id_function = new Id_function_cb() {
        
        @Override
        public long invoke() {
            //id always positive
            long id = Thread.currentThread().getId();
            return id;
        }
    };
    
    int CRYPTO_num_locks();
    void CRYPTO_set_id_callback(Id_function_cb id_function);
    void CRYPTO_set_locking_callback(Locking_function_cb locking_function);*/
}