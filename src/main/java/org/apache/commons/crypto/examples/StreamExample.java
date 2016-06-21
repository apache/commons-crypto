package org.apache.commons.crypto.examples;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Properties;

import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.crypto.cipher.CipherTransformation;
import org.apache.commons.crypto.stream.CryptoInputStream;
import org.apache.commons.crypto.stream.CryptoOutputStream;

/**
 * Example showing how to use stream encryption and decryption.
 */
public class StreamExample {

    private static byte[] getUTF8Bytes(String input) {
        return input.getBytes(StandardCharsets.UTF_8);
    }

    public static void main(String []args) throws IOException {
        final SecretKeySpec key = new SecretKeySpec(getUTF8Bytes("1234567890123456"),"AES");
        final IvParameterSpec iv = new IvParameterSpec(getUTF8Bytes("1234567890123456"));
        Properties properties = new Properties();
        final CipherTransformation transform = CipherTransformation.AES_CBC_PKCS5PADDING;

        String input = "hello world!";
        //Encryption with CryptoOutputStream.

        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

        CryptoOutputStream cos = new CryptoOutputStream(transform, properties, outputStream, key, iv);
        cos.write(getUTF8Bytes(input));
        cos.flush();
        cos.close();

        // The encrypted data:
        System.out.println("Encrypted: "+Arrays.toString(outputStream.toByteArray()));

        // Decryption with CryptoInputStream.
        InputStream inputStream = new ByteArrayInputStream(outputStream.toByteArray());

        CryptoInputStream cis = new CryptoInputStream(transform, properties, inputStream, key, iv);
      
        byte[] decryptedData  = new byte[1024];
        int decryptedLen = 0;
        int i;
        while((i = cis.read(decryptedData, decryptedLen, decryptedData.length - decryptedLen)) > -1 ) {
            decryptedLen += i;
        }
        cis.close();
        System.out.println("Decrypted: "+new String(decryptedData, 0, decryptedLen, StandardCharsets.UTF_8));
    }
}
