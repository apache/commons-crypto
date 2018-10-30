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
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.util.Properties;
import java.util.Random;

import org.apache.commons.crypto.random.CryptoRandom;
import org.apache.commons.crypto.utils.Utils;

import com.sun.jna.NativeLong;
import com.sun.jna.ptr.PointerByReference;

/**
 * <p>
 * OpenSSL secure random using JNA. This implementation is thread-safe.
 * </p>
 *
 * <p>
 * If using an Intel chipset with RDRAND, the high-performance hardware random
 * number generator will be used and it's much faster than SecureRandom. If
 * RDRAND is unavailable, default OpenSSL secure random generator will be used.
 * It's still faster and can generate strong random bytes.
 * </p>
 *
 * @see <a href="https://wiki.openssl.org/index.php/Random_Numbers">
 *      https://wiki.openssl.org/index.php/Random_Numbers</a>
 * @see <a href="http://en.wikipedia.org/wiki/RdRand">
 *      http://en.wikipedia.org/wiki/RdRand</a>
 */
class OpenSslJnaCryptoRandom_1_1 extends Random implements CryptoRandom {
    private static final long serialVersionUID = -7128193502768749585L;
    private final boolean rdrandEnabled;
    private PointerByReference rdrandEngine;

    /**
     * Constructs a {@link OpenSslJnaCryptoRandom_1_1}.
     *
     * @param props the configuration properties (not used)
     * @throws GeneralSecurityException  if could not enable JNA access
     */
    public OpenSslJnaCryptoRandom_1_1(Properties props) //NOPMD
            throws GeneralSecurityException {
        if (!OpenSslJna.isEnabled()) {
            throw new GeneralSecurityException("Could not enable JNA access", OpenSslJna.initialisationError());
        }

        boolean rdrandLoaded = false;
        try {
            //OpenSslNativeJna_1_1.ENGINE_load_rdrand();
            rdrandEngine = OpenSslNativeJna_1_1.ENGINE_by_id("rdrand");
            int ENGINE_METHOD_RAND = 0x0008;
            if(rdrandEngine != null) {
                int rc = OpenSslNativeJna_1_1.ENGINE_init(rdrandEngine);
                
                if(rc != 0) {
                    int rc2 = OpenSslNativeJna_1_1.ENGINE_set_default(rdrandEngine, ENGINE_METHOD_RAND);
                    if(rc2 != 0) {
                        rdrandLoaded = true;
                    }
                }
            }
            
        } catch (Exception e) {
            throw new NoSuchAlgorithmException();
        }
        
        rdrandEnabled = rdrandLoaded;
        
        if(!rdrandLoaded) {
            closeRdrandEngine();
        }
    }

    /**
     * Generates a user-specified number of random bytes. It's thread-safe.
     *
     * @param bytes the array to be filled in with random bytes.
     */
    @Override
    public void nextBytes(byte[] bytes) {
        
        synchronized (OpenSslJnaCryptoRandom_1_1.class) {
            //this method is synchronized for now
            //to support multithreading https://wiki.openssl.org/index.php/Manual:Threads(3) needs to be done
            
            if(rdrandEnabled && OpenSslNativeJna_1_1.RAND_get_rand_method().equals(OpenSslNativeJna_1_1.RAND_OpenSSL())) {
                close();
                throw new RuntimeException("rdrand should be used but default is detected");
            }
            
            ByteBuffer buf = ByteBuffer.allocateDirect(bytes.length);
            int retVal = OpenSslNativeJna_1_1.RAND_bytes(buf, bytes.length);
            throwOnError(retVal);
            buf.rewind();
            buf.get(bytes,0, bytes.length);
        }
    }

    /**
     * Overrides {@link OpenSslJnaCryptoRandom_1_1}. For {@link OpenSslJnaCryptoRandom},
     * we don't need to set seed.
     *
     * @param seed the initial seed.
     */
    @Override
    public void setSeed(long seed) {
        // Self-seeding.
    }

    /**
     * Overrides Random#next(). Generates an integer containing the
     * user-specified number of random bits(right justified, with leading
     * zeros).
     *
     * @param numBits number of random bits to be generated, where 0
     *        {@literal <=} <code>numBits</code> {@literal <=} 32.
     * @return int an <code>int</code> containing the user-specified number of
     *         random bits (right justified, with leading zeros).
     */
    @Override
    final protected int next(int numBits) {
        Utils.checkArgument(numBits >= 0 && numBits <= 32);
        int numBytes = (numBits + 7) / 8;
        byte b[] = new byte[numBytes];
        int next = 0;

        nextBytes(b);
        for (int i = 0; i < numBytes; i++) {
            next = (next << 8) + (b[i] & 0xFF);
        }

        return next >>> (numBytes * 8 - numBits);
    }

    /**
     * Overrides {@link java.lang.AutoCloseable#close()}. Closes OpenSSL context
     * if native enabled.
     */
    @Override
    public void close() {
        closeRdrandEngine();
        //OpenSslNativeJna.ENGINE_cleanup();
        
        //cleanup locks
        //OpenSslNativeJna_1_1.CRYPTO_set_locking_callback(null);
        //LOCK.unlock();
    }

    /**
     * Closes the rdrand engine.
     */
    private void closeRdrandEngine() {
        
        if(rdrandEngine != null) {
            OpenSslNativeJna_1_1.ENGINE_finish(rdrandEngine);
            OpenSslNativeJna_1_1.ENGINE_free(rdrandEngine);
        }
    }

    /**
     * Checks if rdrand engine is used to retrieve random bytes
     * 
     * @return true if rdrand is used, false if default engine is used
     */
    public boolean isRdrandEnabled() {
        return rdrandEnabled;
    }

    /**
     * @param retVal the result value of error.
     */
    private void throwOnError(int retVal) {  
        if (retVal != 1) {
            NativeLong err = OpenSslNativeJna_1_1.ERR_peek_error();
            String errdesc = OpenSslNativeJna_1_1.ERR_error_string(err, null);
            close();
            throw new RuntimeException("return code " + retVal + " from OpenSSL. Err code is " + err + ": " + errdesc);
        }
    }
}
