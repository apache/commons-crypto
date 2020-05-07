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
package org.apache.commons.crypto.stream;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.Channels;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Properties;

import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;
import org.apache.commons.crypto.Crypto;
import org.apache.commons.crypto.cipher.AbstractCipherTest;
import org.apache.commons.crypto.cipher.CryptoCipher;
import org.apache.commons.crypto.stream.input.ChannelInput;
import org.apache.commons.crypto.stream.input.StreamInput;
import org.apache.commons.crypto.stream.output.ChannelOutput;
import org.junit.Assert;
import org.junit.Test;

public class CtrCryptoStreamTest extends AbstractCipherStreamTest {

    @Override
    public void setUp() throws IOException {
        transformation = "AES/CTR/NoPadding";
    }

    @Override
    protected CtrCryptoInputStream getCryptoInputStream(
            final ByteArrayInputStream bais, final CryptoCipher cipher, final int bufferSize,
            final byte[] iv, final boolean withChannel) throws IOException {
        if (withChannel) {
            return new CtrCryptoInputStream(Channels.newChannel(bais), cipher,
                    bufferSize, key, iv);
        }
        return new CtrCryptoInputStream(bais, cipher, bufferSize, key, iv);
    }
    
    @Override
    protected CtrCryptoInputStream getCryptoInputStream(final String transformation, final Properties props, 
            final ByteArrayInputStream bais, final byte[] key, final AlgorithmParameterSpec params,
            boolean withChannel) throws IOException {
        if (withChannel) {
            return new CtrCryptoInputStream(props, Channels.newChannel(bais), key, 
                    ((IvParameterSpec)params).getIV());
        }
        return new CtrCryptoInputStream(props, bais, key, ((IvParameterSpec)params).getIV());
    }

    @Override
    protected CtrCryptoOutputStream getCryptoOutputStream(
            final ByteArrayOutputStream baos, final CryptoCipher cipher, final int bufferSize,
            final byte[] iv, final boolean withChannel) throws IOException {
        if (withChannel) {
            return new CtrCryptoOutputStream(Channels.newChannel(baos), cipher,
                    bufferSize, key, iv);
        }
        return new CtrCryptoOutputStream(baos, cipher, bufferSize, key, iv);
    }
    
    @Override
    protected CtrCryptoOutputStream getCryptoOutputStream(final String transformation,
            final Properties props, final ByteArrayOutputStream baos, final byte[] key, 
            final AlgorithmParameterSpec params, final boolean withChannel) throws IOException {
        if (withChannel) {
            return new CtrCryptoOutputStream(props, Channels.newChannel(baos), key, 
                    ((IvParameterSpec)params).getIV());
        }
        return new CtrCryptoOutputStream(props, baos, key, ((IvParameterSpec)params).getIV());
    }
    
    @Override
    protected void doFieldGetterTest(final String cipherClass, final ByteArrayOutputStream baos,
            final boolean withChannel) throws Exception {
        if (AbstractCipherTest.OPENSSL_CIPHER_CLASSNAME.equals(cipherClass)) {
            if (!Crypto.isNativeCodeLoaded()) {
                return; // Skip this test if no JNI
            }
        }
        
        StreamInput streamInput = new StreamInput(new ByteArrayInputStream(encData), 0);
        try {
            streamInput.seek(0);
            Assert.fail("Expected UnsupportedOperationException.");
        } catch (UnsupportedOperationException ex) {
        	Assert.assertEquals(ex.getMessage(), "Seek is not supported by this implementation");
        }
        try {
            streamInput.read(0, new byte[0], 0, 0);
            Assert.fail("Expected UnsupportedOperationException.");
        } catch (UnsupportedOperationException ex) {
            Assert.assertEquals(ex.getMessage(), "Positioned read is not supported by this implementation");
        }
        Assert.assertEquals(streamInput.available(), encData.length);
        
        ChannelInput channelInput = new ChannelInput(Channels.newChannel(new ByteArrayInputStream(encData)));
        try {
            channelInput.seek(0);
            Assert.fail("Expected UnsupportedOperationException.");
        } catch (UnsupportedOperationException ex) {
            Assert.assertEquals(ex.getMessage(), "Seek is not supported by this implementation");
        }
        try {
            channelInput.read(0, new byte[0], 0, 0);
            Assert.fail("Expected UnsupportedOperationException.");
        } catch (UnsupportedOperationException ex) {
            Assert.assertEquals(ex.getMessage(), "Positioned read is not supported by this implementation");
        }
        Assert.assertEquals(channelInput.available(), 0);
        
        CtrCryptoInputStream in = new CtrCryptoInputStream(channelInput, getCipher(cipherClass), 
                defaultBufferSize, key, iv);
        
        Properties props = new Properties();
        String bufferSize = "4096";
        props.put(CryptoInputStream.STREAM_BUFFER_SIZE_KEY, bufferSize);
        in.setStreamOffset(smallBufferSize);
       
        Assert.assertEquals(CryptoInputStream.getBufferSize(props), Integer.parseInt(bufferSize));
        Assert.assertEquals(smallBufferSize, in.getStreamOffset());
        Assert.assertEquals(in.getBufferSize(), 8192);
        Assert.assertEquals(in.getCipher().getClass(), Class.forName(cipherClass));
        Assert.assertEquals(in.getKey().getAlgorithm(), "AES");
        Assert.assertEquals(in.getParams().getClass(), IvParameterSpec.class);
        Assert.assertNotNull(in.getInput());
    	
        in.close();
    	
        CtrCryptoOutputStream out = new CtrCryptoOutputStream(new ChannelOutput(
                Channels.newChannel(baos)), getCipher(cipherClass), 
                Integer.parseInt(bufferSize), key, iv);
        out.setStreamOffset(smallBufferSize);
        Assert.assertEquals(out.getStreamOffset(), smallBufferSize);
        
        out.close();
    }
    
    @Test(timeout = 120000)
    public void testDecrypt() throws Exception {
        doDecryptTest(AbstractCipherTest.JCE_CIPHER_CLASSNAME, false);
        doDecryptTest(AbstractCipherTest.OPENSSL_CIPHER_CLASSNAME, false);

        doDecryptTest(AbstractCipherTest.JCE_CIPHER_CLASSNAME, true);
        doDecryptTest(AbstractCipherTest.OPENSSL_CIPHER_CLASSNAME, true);
    }
    
    protected void doDecryptTest(final String cipherClass, final boolean withChannel)
            throws IOException {
    	
        CtrCryptoInputStream in = getCryptoInputStream(new ByteArrayInputStream(encData), 
                getCipher(cipherClass), defaultBufferSize, iv, withChannel);
    	
        ByteBuffer buf = ByteBuffer.allocateDirect(dataLen);
        buf.put(encData);
        buf.rewind();
        in.decrypt(buf, 0, dataLen);
        byte[] readData = new byte[dataLen];
        byte[] expectedData = new byte[dataLen];
        buf.get(readData);
        System.arraycopy(data, 0, expectedData, 0, dataLen);
        Assert.assertArrayEquals(readData, expectedData);
        
        try {
            in.decryptBuffer(buf);
            Assert.fail("Expected IOException.");
        } catch (IOException ex) {
            Assert.assertEquals(ex.getCause().getClass(), ShortBufferException.class);	
        }
        
    }
}
