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
package org.apache.commons.crypto;

import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.util.Properties;

import org.apache.commons.crypto.cipher.CryptoCipher;
import org.apache.commons.crypto.cipher.CryptoCipherFactory;
import org.apache.commons.crypto.random.CryptoRandom;
import org.apache.commons.crypto.random.CryptoRandomFactory;
import org.apache.commons.crypto.utils.AES;
import org.apache.commons.crypto.utils.Utils;

/**
 * Provides diagnostic information about Commons Crypto and keys for native
 * class loading.
 */
public final class Crypto {

    private static final class ComponentPropertiesHolder {

        static final Properties PROPERTIES = getComponentProperties();

        /**
         * Gets component properties from component.properties.
         *
         * @return Properties contains project version.
         */
        private static Properties getComponentProperties() {
            final URL url = Crypto.class.getResource("/org/apache/commons/crypto/component.properties");
            final Properties versionData = new Properties();
            if (url != null) {
                try (InputStream inputStream = url.openStream()) {
                    versionData.load(inputStream);
                } catch (final IOException e) { // NOPMD
                }
            }
            return versionData;
        }
    }

    /**
     * The prefix of all crypto configuration keys.
     */
    public static final String CONF_PREFIX = "commons.crypto.";

    /**
     * The configuration key of the file name for loading crypto library.
     */

    public static final String LIB_NAME_KEY = CONF_PREFIX + "lib.name";

    // native lib related configuration keys
    /**
     * The configuration key of the path for loading crypto library.
     */
    public static final String LIB_PATH_KEY = CONF_PREFIX + "lib.path";

    /**
     * The configuration key of temp directory for extracting crypto library.
     * Defaults to "java.io.tempdir" if not found.
     */
    public static final String LIB_TEMPDIR_KEY = CONF_PREFIX + "lib.tempdir";

    // property names related to SSL crypto library loading

    /**
     * Where to find the SSL crypto library when using JNI
     * This is used in Utils.libraryPath()
    */
    public static final String JNI_LIBRARY_PATH_PROPERTY = "jni.library.path";

    /**
     * Override property for the default SSL crypto library name when using JNI
     */
    public static final String JNI_LIBRARY_NAME_PROPERTY = "commons.crypto.OpenSslNativeJni";

    /**
     * Where to find the SSL crypto library when using JNA
     * This is used by the JNA library code
    */
    public static final String JNA_LIBRARY_PATH_PROPERTY = "jna.library.path";

    /**
     * Override property for the default SSL crypto library name when using JNA
     */
    public static final String JNA_LIBRARY_NAME_PROPERTY = CONF_PREFIX + "OpenSslNativeJna";

    /** Default name for loading SSL crypto library using JNA */
    public static final String JNA_LIBRARY_NAME_DEFAULT = "crypto";
    /**
     * Name for loading SSL crypto library using dlopen on macOS
     * JNA automatically adds prefix and suffix; dlopen does not
     */
    public static final String MACOS_LIBRARY_NAME_DEFAULT = "libcrypto.dylib";

    /** If true, print some debug output */
    public static final boolean IS_DEBUG = Boolean.getBoolean(CONF_PREFIX + "debug");

    private static boolean quiet;

    /**
     * Gets the component version of Apache Commons Crypto.
     * <p>
     * This implementation relies on the VERSION properties file which must be set
     * up with the correct contents by the build process. This is done automatically
     * by Maven.
     * </p>
     *
     * @return the version; may be {@code null} if not found
     */
    public static String getComponentName() {
        // Note: the component properties file allows the method to work without needing
        // the jar
        return ComponentPropertiesHolder.PROPERTIES.getProperty("NAME");
    }

    /**
     * Gets the component version of Apache Commons Crypto.
     * <p>
     * This implementation relies on the VERSION properties file which must be set
     * up with the correct contents by the build process. This is done automatically
     * by Maven.
     * </p>
     *
     * @return the version; may be {@code null} if not found
     */
    public static String getComponentVersion() {
        // Note: the component properties file allows the method to work without needing
        // the jar
        return ComponentPropertiesHolder.PROPERTIES.getProperty("VERSION");
    }

    /**
     * The loading error throwable, if loading failed.
     *
     * @return {@code null}, unless loading failed.
     */
    public static Throwable getLoadingError() {
        return NativeCodeLoader.getLoadingError();
    }

    /**
     * Logs info-level messages.
     *
     * @param format See {@link String#format(String, Object...)}.
     * @param args   See {@link String#format(String, Object...)}.
     */
    private static void info(final String format, final Object... args) {
        if (!quiet) { // suppress output for testing
          System.out.println(String.format(format, args));
        }
    }

    /**
     * Checks whether the native code has been successfully loaded for the platform.
     *
     * @return {@code true} if the native code has been loaded successfully.
     */
    public static boolean isNativeCodeLoaded() {
        return NativeCodeLoader.isNativeCodeLoaded();
    }

    /**
     * The Main of Crypto.
     *
     * @param args Not used.
     * @throws Exception if getCryptoRandom or getCryptoCipher get error.
     */
    public static void main(final String[] args) throws Exception {
        quiet = args.length == 1 && args[0].equals("-q");
        info("%s=%s", JNI_LIBRARY_PATH_PROPERTY, System.getProperty(JNI_LIBRARY_PATH_PROPERTY));
        info("%s=%s", JNI_LIBRARY_NAME_PROPERTY, System.getProperty(JNI_LIBRARY_NAME_PROPERTY));
        info("%s %s", getComponentName(), getComponentVersion());
        if (isNativeCodeLoaded()) {
            info("Native code loaded OK: %s", OpenSslInfoNative.NativeVersion());
            info("Native name: %s", OpenSslInfoNative.NativeName());
            info("Native built: %s", OpenSslInfoNative.NativeTimeStamp());
            info("Native header file info: 0x%s %s", Long.toHexString(OpenSslInfoNative.HeaderVersionNumber()), OpenSslInfoNative.HeaderVersionText());
            info("OpenSSL library loaded OK, version: 0x%s", Long.toHexString(OpenSslInfoNative.OpenSSL()));
            info("OpenSSL library info: %s", OpenSslInfoNative.OpenSSLVersion(0));
            info("DLL name: %s", OpenSslInfoNative.DLLName());
            info("DLL path: %s", OpenSslInfoNative.DLLPath());
            info("Additional OpenSSL_version(n) details:");
            for (int j = 1; j < Utils.OPENSSL_VERSION_MAX_INDEX; j++) { // entry 0 is shown above
                final String data = OpenSslInfoNative.OpenSSLVersion(j);
                if (!"not available".equals(data)) {
                    info("OpenSSLVersion(%d): %s", j, data);
                }
            }
            try { // CryptoRandom
                final Properties props = new Properties();
                props.setProperty(CryptoRandomFactory.CLASSES_KEY, CryptoRandomFactory.RandomProvider.OPENSSL.getClassName());
                try (CryptoRandom cryptoRandom = CryptoRandomFactory.getCryptoRandom(props)) {
                    info("Random instance created OK: %s", cryptoRandom);
                }
            } catch (final Exception e) {
                info("Failed: %s", e);
            }
            try { // CryptoCipher
                final Properties props = new Properties();
                props.setProperty(CryptoCipherFactory.CLASSES_KEY, CryptoCipherFactory.CipherProvider.OPENSSL.getClassName());
                try (CryptoCipher cryptoCipher = CryptoCipherFactory.getCryptoCipher(AES.CTR_NO_PADDING, props)) {
                    info("Cipher %s instance created OK: %s", AES.CTR_NO_PADDING, cryptoCipher);
                }
            } catch (final Exception e) {
                info("Failed: %s", e);
            }
        } else {
            final Throwable error = getLoadingError();
            String msg = "";
            if (error != null) {
                msg = error.getMessage();
            }
            info("Native load failed: %s %s", error, msg);
        }
    }

    /**
     * Constructs a new instance.
     *
     * @deprecated Will be private in the next major release.
     */
    @Deprecated
    public Crypto() {
        // empty
    }

}
