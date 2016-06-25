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
package org.apache.commons.crypto.utils;

import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Method;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.Properties;

import org.apache.commons.crypto.cipher.CryptoCipher;
import org.apache.commons.crypto.cipher.CryptoCipherFactory;
import org.apache.commons.crypto.conf.ConfigurationKeys;

/**
 * General utility methods.
 */
public final class Utils {

    /**
     * For AES, the algorithm block is fixed size of 128 bits.
     *
     * @see <a href="http://en.wikipedia.org/wiki/Advanced_Encryption_Standard">
     *      http://en.wikipedia.org/wiki/Advanced_Encryption_Standard</a>
     */
    private static final int AES_BLOCK_SIZE = 16;

    /**
     * The private constructor of {@Link Utils}.
     */
    private Utils() {
    }

    static {
        loadSystemProperties();
    }

    /**
     * loads system properties when configuration file of the name
     * {@link ConfigurationKeys#SYSTEM_PROPERTIES_FILE} is found.
     */
    private static void loadSystemProperties() {
        new Throwable().printStackTrace();
        try {
            InputStream is = Thread.currentThread().getContextClassLoader()
                    .getResourceAsStream(ConfigurationKeys.SYSTEM_PROPERTIES_FILE);

            if (is == null) {
                return; // no configuration file is found
            }
            // Load property file
            Properties props = new Properties();
            props.load(is);
            is.close();
            Enumeration<?> names = props.propertyNames();
            while (names.hasMoreElements()) {
                String name = (String) names.nextElement();
                if (name.startsWith(ConfigurationKeys.CONF_PREFIX) && System.getProperty(name) == null) {
                    System.setProperty(name, props.getProperty(name));
                }
            }
        } catch (Throwable ex) {
            System.err.println("Could not load '"
                    + ConfigurationKeys.SYSTEM_PROPERTIES_FILE
                    + "' from classpath: " + ex.toString());
        }
    }

    /**
     * Forcibly free the direct buffer.
     *
     * @param buffer the bytebuffer to be freed.
     */
    public static void freeDirectBuffer(ByteBuffer buffer) {
        try {
            /* Using reflection to implement sun.nio.ch.DirectBuffer.cleaner()
            .clean(); */
            final String SUN_CLASS = "sun.nio.ch.DirectBuffer";
            Class<?>[] interfaces = buffer.getClass().getInterfaces();

            for (Class<?> clazz : interfaces) {
                if (clazz.getName().equals(SUN_CLASS)) {
                    final Object[] NO_PARAM = new Object[0];
                    /* DirectBuffer#cleaner() */
                    Method getCleaner = Class.forName(SUN_CLASS).getMethod("cleaner");
                    Object cleaner = getCleaner.invoke(buffer, NO_PARAM);
                    /* Cleaner#clean() */
                    Method cleanMethod = Class.forName("sun.misc.Cleaner").getMethod("clean");
                    cleanMethod.invoke(cleaner, NO_PARAM);
                    return;
                }
            }
        } catch (ReflectiveOperationException e) { // NOPMD
            // Ignore the Reflection exception.

        }
    }

    /**
     * <p>
     * This method is only for Counter (CTR) mode. Generally the CryptoCipher
     * calculates the IV and maintain encryption context internally.For example
     * a Cipher will maintain its encryption context internally when we do
     * encryption/decryption using the CryptoCipher#update interface.
     * </p>
     * <p>
     * Encryption/Decryption is not always on the entire file. For example, in
     * Hadoop, a node may only decrypt a portion of a file (i.e. a split). In
     * these situations, the counter is derived from the file position.
     * </p>
     * The IV can be calculated by combining the initial IV and the counter with
     * a lossless operation (concatenation, addition, or XOR).
     *
     * @see <a
     *      href="http://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Counter_.28CTR.29">
     *      http://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Counter_.28CTR.29</a>
     *
     * @param initIV initial IV
     * @param counter counter for input stream position
     * @param IV the IV for input stream position
     */
    public static void calculateIV(byte[] initIV, long counter, byte[] IV) {
        checkArgument(initIV.length == AES_BLOCK_SIZE);
        checkArgument(IV.length == AES_BLOCK_SIZE);

        int i = IV.length; // IV length
        int j = 0; // counter bytes index
        int sum = 0;
        while (i-- > 0) {
            // (sum >>> Byte.SIZE) is the carry for addition
            sum = (initIV[i] & 0xff) + (sum >>> Byte.SIZE); // NOPMD
            if (j++ < 8) { // Big-endian, and long is 8 bytes length
                sum += (byte) counter & 0xff;
                counter >>>= 8;
            }
            IV[i] = (byte) sum;
        }
    }

    /**
     * Helper method to create a CryptoCipher instance and throws only
     * IOException.
     *
     * @param props The <code>Properties</code> class represents a set of
     *        properties.
     * @param transformation the name of the transformation, e.g.,
     * <i>AES/CBC/PKCS5Padding</i>.
     * See the Java Cryptography Architecture Standard Algorithm Name Documentation
     * for information about standard transformation names.
     * @return the CryptoCipher instance.
     * @throws IOException if an I/O error occurs.
     */
    public static CryptoCipher getCipherInstance(
            String transformation, Properties props)
            throws IOException {
        try {
            return CryptoCipherFactory.getInstance(transformation, props);
        } catch (GeneralSecurityException e) {
            throw new IOException(e);
        }
    }

    /**
     * Ensures the truth of an expression involving one or more parameters to
     * the calling method.
     *
     * @param expression a boolean expression.
     * @throws IllegalArgumentException if expression is false.
     */
    public static void checkArgument(boolean expression) {
        if (!expression) {
            throw new IllegalArgumentException();
        }
    }

    /**
     * Checks the truth of an expression.
     *
     * @param expression a boolean expression.
     * @param errorMessage the exception message to use if the check fails; will
     *        be converted to a string using <code>String
     *                     .valueOf(Object)</code>.
     * @throws IllegalArgumentException if expression is false.
     */
    public static void checkArgument(boolean expression, Object errorMessage) {
        if (!expression) {
            throw new IllegalArgumentException(String.valueOf(errorMessage));
        }
    }

    /**
     * Ensures that an object reference passed as a parameter to the calling
     * method is not null.
     *
     * @param <T> the type of the object reference to be checked.
     * @param reference an object reference.
     * @return the non-null reference that was validated.
     * @throws NullPointerException if reference is null.
     */
    public static <T> T checkNotNull(T reference) {
        if (reference == null) {
            throw new NullPointerException();
        }
        return reference;
    }

    /**
     * Ensures the truth of an expression involving the state of the calling
     * instance, but not involving any parameters to the calling method.
     *
     * @param expression a boolean expression.
     * @throws IllegalStateException if expression is false.
     */
    public static void checkState(boolean expression) {
        if (!expression) {
            throw new IllegalStateException();
        }
    }

    /**
     * Splits class names sequence into substrings, Trim each substring into an
     * entry,and returns an list of the entries.
     *
     * @param clazzNames a string consist of a list of the entries joined by a
     *        delimiter.
     * @param separator a delimiter for the input string.
     * @return a list of class entries.
     */
    public static List<String> splitClassNames(String clazzNames,
            String separator) {
        List<String> res = new ArrayList<>();
        if (clazzNames == null || clazzNames.isEmpty()) {
            return res;
        }

        for (String clazzName : clazzNames.split(separator)) {
            clazzName = clazzName.trim();
            if (!clazzName.isEmpty()) {
                res.add(clazzName);
            }
        }
        return res;
    }

    /**
     * Returns true if Fallback is enabled when native failed.
     * @param props The <code>Properties</code> class represents a set of
     *        properties.
     * @return true if Fallback is enabled when native failed.
     */
    public static boolean isFallbackEnabled(Properties props) {
        String enableFallback = props.getProperty(ConfigurationKeys.
            ENABLE_FALLBACK_ON_NATIVE_FAILED_KEY);
        if (enableFallback == null || enableFallback.isEmpty()) {
            enableFallback = System.getProperty(ConfigurationKeys.
                ENABLE_FALLBACK_ON_NATIVE_FAILED_KEY);
        }
        if (enableFallback == null || enableFallback.isEmpty()) {
            return ConfigurationKeys
                    .ENABLE_FALLBACK_ON_NATIVE_FAILED_DEFAULT;
        }
        return Boolean.valueOf(enableFallback);
    }
}
