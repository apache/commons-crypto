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

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;
import java.util.UUID;

import org.apache.commons.crypto.utils.IoUtils;
import org.apache.commons.crypto.utils.Utils;

/**
 * A helper to load the native code i.e. libcommons-crypto.so. This handles the
 * fallback to either the bundled libcommons-crypto-Linux-i386-32.so or the
 * default java implementations where appropriate.
 */
final class NativeCodeLoader {

    private final static boolean nativeCodeLoaded;

    private static final Throwable loadingError;

    /**
     * The private constructor of {@link NativeCodeLoader}.
     */
    private NativeCodeLoader() {
    }

    static {
        loadingError = loadLibrary(); // will be null if loaded OK

        nativeCodeLoaded = loadingError == null;
    }

    /**
     * Loads the library if possible.
     *
     * @return null if successful, otherwise the Throwable that was caught
     */
    static Throwable loadLibrary() {
        try {
            final File nativeLibFile = findNativeLibrary();
            if (nativeLibFile != null) {
                // Load extracted or specified native library.
                System.load(nativeLibFile.getAbsolutePath());
            } else {
                // Load preinstalled library (in the path -Djava.library.path)
                System.loadLibrary("commons-crypto");
            }
            return null; // OK
        } catch (final Exception t) {
            return t;
        } catch (final UnsatisfiedLinkError t) {
            return t;
        }
    }

    /**
     * Finds the native library.
     *
     * @return the jar file.
     */
    private static File findNativeLibrary() {
        // Get the properties once
        final Properties props = Utils.getDefaultProperties();

        // Try to load the library in commons-crypto.lib.path */
        String nativeLibraryPath = props.getProperty(Crypto.LIB_PATH_KEY);
        String nativeLibraryName = props.getProperty(Crypto.LIB_NAME_KEY);

        // Resolve the library file name with a suffix (e.g., dll, .so, etc.)
        if (nativeLibraryName == null) {
            nativeLibraryName = System.mapLibraryName("commons-crypto");
        }
        if (nativeLibraryPath != null) {
            final File nativeLib = new File(nativeLibraryPath, nativeLibraryName);
            if (nativeLib.exists()) {
                return nativeLib;
            }
        }

        // Load an OS-dependent native library inside a jar file
        nativeLibraryPath = "/org/apache/commons/crypto/native/"
                + OsInfo.getNativeLibFolderPathForCurrentOS();
        boolean hasNativeLib = hasResource(nativeLibraryPath + "/"
                + nativeLibraryName);
        if (!hasNativeLib) {
            final String altName = "libcommons-crypto.jnilib";
            if (OsInfo.getOSName().equals("Mac") && hasResource(nativeLibraryPath + "/" + altName)) {
                // Fix for openjdk7 for Mac
                nativeLibraryName = altName;
                hasNativeLib = true;
            }
        }

        if (!hasNativeLib) {
            final String errorMessage = String.format(
                    "no native library is found for os.name=%s and os.arch=%s",
                    OsInfo.getOSName(), OsInfo.getArchName());
            throw new RuntimeException(errorMessage);
        }

        // Temporary folder for the native lib. Use the value of
        // commons-crypto.tempdir or java.io.tmpdir
        final String tempFolder = new File(props.getProperty(Crypto.LIB_TEMPDIR_KEY,
        System.getProperty("java.io.tmpdir"))).getAbsolutePath();

        // Extract and load a native library inside the jar file
        return extractLibraryFile(nativeLibraryPath, nativeLibraryName,
                tempFolder);
    }

    /**
     * Extracts the specified library file to the target folder.
     *
     * @param libFolderForCurrentOS the library in commons-crypto.lib.path.
     * @param libraryFileName the library name.
     * @param targetFolder Target folder for the native lib. Use the value of
     *        commons-crypto.tempdir or java.io.tmpdir.
     * @return the library file.
     */
    private static File extractLibraryFile(final String libFolderForCurrentOS,
            final String libraryFileName, final String targetFolder) {
        final String nativeLibraryFilePath = libFolderForCurrentOS + "/"
                + libraryFileName;

        // Attach UUID to the native library file to ensure multiple class
        // loaders
        // can read the libcommons-crypto multiple times.
        final String uuid = UUID.randomUUID().toString();
        final String extractedLibFileName = String.format("commons-crypto-%s-%s",
                uuid, libraryFileName);
        final File extractedLibFile = new File(targetFolder, extractedLibFileName);

        InputStream reader = null;
        try {
            // Extract a native library file into the target directory
            reader = NativeCodeLoader.class
                    .getResourceAsStream(nativeLibraryFilePath);
            final FileOutputStream writer = new FileOutputStream(extractedLibFile);
            try {
                final byte[] buffer = new byte[8192];
                int bytesRead;
                while ((bytesRead = reader.read(buffer)) != -1) {
                    writer.write(buffer, 0, bytesRead);
                }
            } finally {
                // Delete the extracted lib file on JVM exit.
                extractedLibFile.deleteOnExit();

                writer.close();

                IoUtils.cleanup(reader);
                reader = null;
            }

            // Set executable (x) flag to enable Java to load the native library
            if (!extractedLibFile.setReadable(true)
                    || !extractedLibFile.setExecutable(true)
                    || !extractedLibFile.setWritable(true, true)) {
                throw new RuntimeException("Invalid path for library path");
            }

            // Check whether the contents are properly copied from the resource
            // folder
            {
                InputStream nativeIn = null;
                InputStream extractedLibIn = null;
                try {
                    nativeIn = NativeCodeLoader.class
                            .getResourceAsStream(nativeLibraryFilePath);
                    extractedLibIn = new FileInputStream(extractedLibFile);
                    if (!contentsEquals(nativeIn, extractedLibIn)) {
                        throw new RuntimeException(String.format(
                                "Failed to write a native library file at %s",
                                extractedLibFile));
                    }
                } finally {
                    if (nativeIn != null) {
                        nativeIn.close();
                    }
                    if (extractedLibIn != null) {
                        extractedLibIn.close();
                    }
                }
            }

            return extractedLibFile;
        } catch (final IOException e) {
            return null;
        } finally {
            IoUtils.cleanup(reader);
        }
    }

    /**
     * Checks whether in1 and in2 is equal.
     *
     * @param in1 the input1.
     * @param in2 the input2.
     * @return true if in1 and in2 is equal, else false.
     * @throws IOException if an I/O error occurs.
     */
    private static boolean contentsEquals(InputStream in1, InputStream in2)
            throws IOException {
        if (!(in1 instanceof BufferedInputStream)) {
            in1 = new BufferedInputStream(in1);
        }
        if (!(in2 instanceof BufferedInputStream)) {
            in2 = new BufferedInputStream(in2);
        }

        int ch = in1.read();
        while (ch != -1) {
            final int ch2 = in2.read();
            if (ch != ch2) {
                return false;
            }
            ch = in1.read();
        }
        final int ch2 = in2.read();
        return ch2 == -1;
    }

    /**
     * Checks whether the given path has resource.
     *
     * @param path the path.
     * @return the boolean.
     */
    private static boolean hasResource(final String path) {
        return NativeCodeLoader.class.getResource(path) != null;
    }

    /**
     * Checks whether native code is loaded for this platform.
     *
     * @return {@code true} if native is loaded, else {@code false}.
     */
    static boolean isNativeCodeLoaded() {
        return nativeCodeLoaded;
    }

    /**
     * Gets the error cause if loading failed.
     *
     * @return null, unless loading failed
     */
    static Throwable getLoadingError() {
        return loadingError;
    }
}
