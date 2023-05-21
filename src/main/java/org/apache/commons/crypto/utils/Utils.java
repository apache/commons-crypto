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
package org.apache.commons.crypto.utils;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.Objects;
import java.util.Properties;

import org.apache.commons.crypto.Crypto;
import org.apache.commons.crypto.cipher.CryptoCipher;
import org.apache.commons.crypto.cipher.CryptoCipherFactory;

/**
 * General utility methods.
 */
public final class Utils {

    private static class DefaultPropertiesHolder {
        static final Properties DEFAULT_PROPERTIES = createDefaultProperties();

        /**
         * Loads system properties when configuration file of the name
         * {@link #SYSTEM_PROPERTIES_FILE} is found.
         *
         * @return the default properties
         */
        private static Properties createDefaultProperties() {
          // default to system
          final Properties defaultedProps = new Properties(System.getProperties());
          final URL url = Thread.currentThread().getContextClassLoader().getResource(SYSTEM_PROPERTIES_FILE);
          if (url == null) {
              // Fail early when the resource is not found which makes SpotBugs happy on Java 17.
              return defaultedProps;
          }
          try {
              final Properties fileProps = new Properties();
              try (InputStream is = url.openStream()) {
                  fileProps.load(is);
              }
              final Enumeration<?> names = fileProps.propertyNames();
              while (names.hasMoreElements()) {
                  final String name = (String) names.nextElement();
                  // ensure System properties override ones in the file so one can override the file on the command line
                  if (System.getProperty(name) == null) {
                      defaultedProps.setProperty(name, fileProps.getProperty(name));
                  }
              }
          } catch (final Exception ex) {
              System.err.println("Could not load '" + SYSTEM_PROPERTIES_FILE + "' from classpath: " + ex);
          }
          return defaultedProps;
      }
   }

    /**
     * The file name of configuration file.
     */
    private static final String SYSTEM_PROPERTIES_FILE = Crypto.CONF_PREFIX + "properties";

    /**
     * Ensures the truth of an expression involving one or more parameters to
     * the calling method.
     *
     * @param expression a boolean expression.
     * @throws IllegalArgumentException if expression is false.
     */
    public static void checkArgument(final boolean expression) {
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
    public static void checkArgument(final boolean expression, final Object errorMessage) {
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
     * @deprecated Use {@link Objects#requireNonNull(Object)}.
     */
    @Deprecated
    public static <T> T checkNotNull(final T reference) {
        return Objects.requireNonNull(reference, "reference");
    }

    /**
     * Ensures the truth of an expression involving the state of the calling
     * instance, but not involving any parameters to the calling method.
     *
     * @param expression a boolean expression.
     * @throws IllegalStateException if expression is false.
     */
    public static void checkState(final boolean expression) {
        checkState(expression, null);
    }

    /**
     * Ensures the truth of an expression involving the state of the calling
     * instance, but not involving any parameters to the calling method.
     *
     * @param expression a boolean expression.
     * @param message Error message for the exception when the expression is false.
     * @throws IllegalStateException if expression is false.
     */
    public static void checkState(final boolean expression, final String message) {
        if (!expression) {
            throw new IllegalStateException(message);
        }
    }

    /**
     * Helper method to create a CryptoCipher instance and throws only
     * IOException.
     *
     * @param properties The {@code Properties} class represents a set of
     *        properties.
     * @param transformation the name of the transformation, e.g.,
     * <i>AES/CBC/PKCS5Padding</i>.
     * See the Java Cryptography Architecture Standard Algorithm Name Documentation
     * for information about standard transformation names.
     * @return the CryptoCipher instance.
     * @throws IOException if an I/O error occurs.
     */
    public static CryptoCipher getCipherInstance(final String transformation, final Properties properties) throws IOException {
        try {
            return CryptoCipherFactory.getCryptoCipher(transformation, properties);
        } catch (final GeneralSecurityException e) {
            throw new IOException(e);
        }
    }

    /**
     * Gets a properties instance that defaults to the System Properties
     * plus any other properties found in the file
     * {@link #SYSTEM_PROPERTIES_FILE}
     * @return a Properties instance with defaults
     */
    public static Properties getDefaultProperties() {
        return new Properties(DefaultPropertiesHolder.DEFAULT_PROPERTIES);
    }

    /**
     * Gets the properties merged with default properties.
     * @param newProp  User-defined properties
     * @return User-defined properties with the default properties
     */
    public static Properties getProperties(final Properties newProp) {
        final Properties properties = new Properties(DefaultPropertiesHolder.DEFAULT_PROPERTIES);
        properties.putAll(newProp);
        return properties;
     }

    /*
     * Override the default DLL name if jni.library.path is a valid directory
     * @param name - the default name, passed from native code
     * @return the updated library path
     * This method is designed for use from the DynamicLoader native code.
     * Although it could all be implemented in native code, this hook method
     * makes maintenance easier.
     * The code is intended for use with macOS where SIP makes it hard to override
     * the environment variables needed to override the DLL search path. It also
     * works for Linux, but is not (currently) used or needed for Windows.
     * Do not change the method name or its signature!
     */
    static String libraryPath(final String name) {
        final String override = System.getProperty("jni.library.path");
        if (override != null && new File(override).isDirectory()) {
            return new File(override, name).getPath();
        }
        return name;
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
    public static List<String> splitClassNames(final String clazzNames, final String separator) {
        final List<String> res = new ArrayList<>();
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
     * The private constructor of {@link Utils}.
     */
    private Utils() {
    }

}
