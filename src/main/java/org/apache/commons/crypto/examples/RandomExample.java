package org.apache.commons.crypto.examples;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.Properties;

import org.apache.commons.crypto.conf.ConfigurationKeys;
import org.apache.commons.crypto.random.CryptoRandom;
import org.apache.commons.crypto.random.CryptoRandomFactory;

public class RandomExample {

    public static void main(String []args) throws GeneralSecurityException, IOException {
        //Constructs a byte array to store random data.
        byte[] key = new byte[16];
        byte[] iv = new byte[16];
        Properties properties = new Properties();
        properties.put(ConfigurationKeys.COMMONS_CRYPTO_SECURE_RANDOM_CLASSES_KEY,
                "org.apache.commons.crypto.random.OpensslCryptoRandom"); // TODO replace with alias
        //Gets the 'CryptoRandom' instance.
        CryptoRandom random = CryptoRandomFactory.getCryptoRandom(properties);
        System.out.println(random.getClass().getCanonicalName());

        //Generates random bytes and places them into the byte array.
        random.nextBytes(key);
        random.nextBytes(iv);
        //Closes the CryptoRandom.
        random.close();

        // Show the output
        System.out.println(Arrays.toString(key));
        System.out.println(Arrays.toString(iv));
    }
}
