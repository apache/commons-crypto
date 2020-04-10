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
package org.apache.commons.crypto;

import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.util.Properties;

import org.apache.commons.crypto.cipher.CryptoCipherFactory;
import org.apache.commons.crypto.random.CryptoRandomFactory;

/**
 * Provides diagnostic information about Commons Crypto and keys for native class loading
 */
public final class Crypto {

    /**
     * The prefix of all crypto configuration keys
     */
    public static final String CONF_PREFIX = "commons.crypto.";

    // native lib related configuration keys
    /**
     * The configuration key of the path for loading crypto library.
     */
    public static final String LIB_PATH_KEY = Crypto.CONF_PREFIX
            + "lib.path";
    /**
     * The configuration key of the file name for loading crypto library.
     */
    public static final String LIB_NAME_KEY = Crypto.CONF_PREFIX
            + "lib.name";
    /**
     * The configuration key of temp directory for extracting crypto library.
     * Defaults to "java.io.tempdir" if not found.
     */
    public static final String LIB_TEMPDIR_KEY = Crypto.CONF_PREFIX
            + "lib.tempdir";

    private static class ComponentPropertiesHolder {
        static final Properties PROPERTIES = getComponentProperties();

        /**
         * Get component properties from component.properties.
         *
         * @return Properties contains project version.
         */
        private static Properties getComponentProperties() {
            final URL url = Crypto.class.getResource("/org/apache/commons/crypto/component.properties");
            if (url != null) {
                final Properties versionData = new Properties();
                try (InputStream openStream = url.openStream()) {
                    versionData.load(openStream);
                    return versionData;
                } catch (final IOException e) {  // NOPMD
                }
            }
            return new Properties(); // make sure field is not null
        }
     }

    /**
     * Checks whether the native code has been successfully loaded for the platform.
     *
     * @return true if the native code has been loaded successfully.
     */
    public static boolean isNativeCodeLoaded() {
        return NativeCodeLoader.isNativeCodeLoaded();
    }

    /**
     * The loading error throwable, if loading failed.
     *
     * @return null, unless loading failed.
     */
    public static Throwable getLoadingError() {
        return NativeCodeLoader.getLoadingError();
    }

    /**
     * Gets the component version of Apache Commons Crypto.
     * <p>
     * This implementation relies on the VERSION properties file which
     * must be set up with the correct contents by the build process.
     * This is done automatically by Maven.
     *
     * @return the version; may be null if not found
     */
    public static String getComponentVersion() {
        // Note: the component properties file allows the method to work without needing the jar
        return ComponentPropertiesHolder.PROPERTIES.getProperty("VERSION");
    }

    /**
     * Gets the component version of Apache Commons Crypto.
     * <p>
     * This implementation relies on the VERSION properties file which
     * must be set up with the correct contents by the build process.
     * This is done automatically by Maven.
     *
     * @return the version; may be null if not found
     */
    public static String getComponentName() {
        // Note: the component properties file allows the method to work without needing the jar
        return ComponentPropertiesHolder.PROPERTIES.getProperty("NAME");
    }

    /**
     * The Main of Crypto
     * @param args don't use the args
     * @throws Exception if getCryptoRandom or getCryptoCipher get error.
     */
    public static void main(final String args[]) throws Exception {
        System.out.println(getComponentName() + " " + getComponentVersion());
        if (isNativeCodeLoaded()) {
            System.out.println("Native code loaded OK " + OpenSslInfoNative.NativeVersion());
            System.out.println("Native Name " + OpenSslInfoNative.NativeName());
            System.out.println("Native Built " + OpenSslInfoNative.NativeTimeStamp());
            System.out.println("OpenSSL library loaded OK, version: 0x" + Long.toHexString(OpenSslInfoNative.OpenSSL()));
            System.out.println("OpenSSL library info " + OpenSslInfoNative.OpenSSLVersion(0));
            {
                final Properties props = new Properties();
                props.setProperty(CryptoRandomFactory.CLASSES_KEY, CryptoRandomFactory.RandomProvider.OPENSSL.getClassName());
                CryptoRandomFactory.getCryptoRandom(props);
                System.out.println("Random instance created OK");
            }
            {
                final Properties props = new Properties();
                props.setProperty(CryptoCipherFactory.CLASSES_KEY, CryptoCipherFactory.CipherProvider.OPENSSL.getClassName());
                CryptoCipherFactory.getCryptoCipher("AES/CTR/NoPadding", props);
                System.out.println("Cipher instance created OK");
            }
            System.out.println("Additional OpenSSL_version(n) details:");
            for(int j=1;j<6;j++) {
                System.out.println(j+": "+ OpenSslInfoNative.OpenSSLVersion(j));
            }
        } else {
            System.out.println("Native load failed: " + getLoadingError());
        }
    }
}
