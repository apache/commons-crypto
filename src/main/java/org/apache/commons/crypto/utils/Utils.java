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
import java.security.GeneralSecurityException;
import java.util.ArrayList;
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
     * The private constructor of {@Link Utils}.
     */
    private Utils() {
    }

    private static class DefaultPropertiesHolder {
        static final Properties instance = getDefaultProperties();
    }

    /**
     * Loads system properties when configuration file of the name
     * {@link ConfigurationKeys#SYSTEM_PROPERTIES_FILE} is found.
     * 
     * @return the default properties
     */
    private static Properties getDefaultProperties() {
        // default to system
        Properties props = new Properties(System.getProperties());
        try {
            InputStream is = Thread.currentThread().getContextClassLoader()
                    .getResourceAsStream(ConfigurationKeys.SYSTEM_PROPERTIES_FILE);

            if (is == null) {
                return props; // no configuration file is found
            }
            // Load property file
            props.load(is);
            is.close();
        } catch (Throwable ex) {
            System.err.println("Could not load '"
                    + ConfigurationKeys.SYSTEM_PROPERTIES_FILE
                    + "' from classpath: " + ex.toString());
        }
        return props;
    }

    /**
     * Gets the properties merged with default properties.
     * @param newProp User-defined properties
     * @return User-defined properties merged with defaults.
     */
    public static Properties getProperties(Properties newProp) {
        Properties properties = new Properties(DefaultPropertiesHolder.instance);
        properties.putAll(newProp);
        return properties;
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
     *        delimiter, may be null or empty in which case an empty list is returned.
     * @param separator a delimiter for the input string.
     * @return a list of class entries.
     */
    public static List<String> splitClassNames(String clazzNames, String separator) {
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

}
