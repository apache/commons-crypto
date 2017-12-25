package org.apache.commons.crypto.stream;

import org.apache.commons.crypto.cipher.CryptoCipher;

import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.channels.Channel;
import java.nio.channels.Channels;
import java.security.spec.AlgorithmParameterSpec;

public class GcmNoPaddingCipherStreamTest extends AbstractCipherStreamTest{

    private int tLen ;

    @Override
    public void setUp() throws IOException {
        transformation = "AES/GCM/NoPadding";
        tLen = 128;   //the verification bit is 16 bytes.
        algorithmParameterSpec = new GCMParameterSpec(tLen,super.iv,0,12);
    }

    protected CryptoInputStream getCryptoInputStream(ByteArrayInputStream bais,
                                                     CryptoCipher cipher, int bufferSize, byte[] iv, boolean withChannel)
            throws IOException {
        if (withChannel) {
            return new CryptoInputStream(Channels.newChannel(bais), cipher,
                    bufferSize, new SecretKeySpec(key, "AES"),
                    super.algorithmParameterSpec,bais.available());
        }
        return new CryptoInputStream(bais, cipher, bufferSize,
                new SecretKeySpec(key, "AES"), super.algorithmParameterSpec);
    }

    protected CryptoOutputStream getCryptoOutputStream(
            ByteArrayOutputStream baos, CryptoCipher cipher, int bufferSize,
            byte[] iv, boolean withChannel) throws IOException {
        if (withChannel) {
            return new CryptoOutputStream(Channels.newChannel(baos), cipher,
                    bufferSize, new SecretKeySpec(key, "AES"),
                    super.algorithmParameterSpec);
        }
        return new CryptoOutputStream(baos, cipher, bufferSize,
                new SecretKeySpec(key, "AES"), super.algorithmParameterSpec);
    }

}
