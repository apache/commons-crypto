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
import java.security.NoSuchAlgorithmException;
import java.util.Properties;
import java.util.Random;

import org.apache.commons.crypto.random.CryptoRandom;
import org.apache.commons.crypto.utils.Utils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import com.sun.jna.NativeLong;
import com.sun.jna.ptr.PointerByReference;

/**
 * <p>
 * OpenSSL secure random using JNI. This implementation is thread-safe.
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
public class OpensslJnaCryptoRandom extends Random implements CryptoRandom {
    private static final long serialVersionUID = -7128193502768749585L;
    private static final Log LOG = LogFactory.getLog(OpensslJnaCryptoRandom.class
            .getName());
    private final boolean rdrandEnabled;
    private PointerByReference rdrandEngine;

    /**
     * Constructs a {@link OpensslJnaCryptoRandom}.
     *
     * @param props the configuration properties.
     * @throws NoSuchAlgorithmException if no Provider supports a
     *         SecureRandomSpi implementation for the specified algorithm.
     */
    public OpensslJnaCryptoRandom(Properties props)
            throws NoSuchAlgorithmException {

        boolean rdrandLoaded = false;
        try {
            OpensslNativeJna.ENGINE_load_rdrand();
            rdrandEngine = OpensslNativeJna.ENGINE_by_id("rdrand");
            int ENGINE_METHOD_RAND = 0x0008;
            if(rdrandEngine != null) {
                int rc = OpensslNativeJna.ENGINE_init(rdrandEngine);
                
                if(rc != 0) {
                    int rc2 = OpensslNativeJna.ENGINE_set_default(rdrandEngine, ENGINE_METHOD_RAND);
                    if(rc2 != 0) {
                        rdrandLoaded = true;
                    }
                }
            } else {
                LOG.debug("Unable to find rdrand engine");
            }
            
        } catch (Throwable e) {
            LOG.debug("Unable load or initialize rdrand engine due to "+e,e);
        }
        
        LOG.debug("Will use rdrand engine: "+rdrandLoaded);
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
        
        synchronized (OpensslJnaCryptoRandom.class) {
            //this method is synchronized for now
            //to support multithreading https://wiki.openssl.org/index.php/Manual:Threads(3) needs to be done
            
            if(rdrandEnabled && OpensslNativeJna.RAND_get_rand_method().equals(OpensslNativeJna.RAND_SSLeay())) {
                close();
                throw new RuntimeException("rdrand should be used but default is detected");
            }
            
            ByteBuffer buf = ByteBuffer.allocateDirect(bytes.length);
            int retVal = OpensslNativeJna.RAND_bytes(buf, bytes.length);
            throwOnError(retVal);
            buf.rewind();
            buf.get(bytes,0, bytes.length);
        }
    }

    /**
     * Overrides {@link OpensslJnaCryptoRandom}. For {@link OpensslJnaCryptoRandom},
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
     * Overrides {@link java.lang.AutoCloseable#close()}. Closes openssl context
     * if native enabled.
     */
    @Override
    public void close() {
        closeRdrandEngine();
        OpensslNativeJna.ENGINE_cleanup();
        
        //cleanup locks
        //OpensslNativeJna.CRYPTO_set_locking_callback(null);
        //LOCK.unlock();
    }
    
    private void closeRdrandEngine() {
        
        if(rdrandEngine != null) {
            OpensslNativeJna.ENGINE_finish(rdrandEngine);
            OpensslNativeJna.ENGINE_free(rdrandEngine);
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
    
    private void throwOnError(int retVal) {  
        if(retVal != 1) {
            NativeLong err = OpensslNativeJna.ERR_peek_error();
            String errdesc = OpensslNativeJna.ERR_error_string(err, null);
            close();
            throw new RuntimeException("return code "+retVal+" from openssl. Err code is "+err+": "+errdesc);
        }
    }
}
