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

import java.io.BufferedInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFileAttributes;
import java.util.Objects;
import java.util.Properties;
import java.util.UUID;

import org.apache.commons.crypto.utils.Utils;

/**
 * A helper to load the native code i.e. libcommons-crypto.so. This handles the
 * fallback to either the bundled libcommons-crypto-Linux-i386-32.so or the
 * default java implementations where appropriate.
 */
final class NativeCodeLoader {

    /**
     * End of file pseudo-character.
     */
    private static final int EOF = -1;

    private static final Throwable loadingError;

    private final static boolean nativeCodeLoaded;

    static {
        loadingError = loadLibrary(); // will be null if loaded OK

        nativeCodeLoaded = loadingError == null;
    }

    /**
     * Returns the given InputStream if it is already a {@link BufferedInputStream},
     * otherwise creates a {@link java.io.BufferedInputStream} from the given {@link java.io.InputStream}.
     *
     * @param inputStream the {@link InputStream} to wrap or return (not {@code null})
     * @return the given {@link InputStream} or a new {@link BufferedInputStream} for the
     *         given {@link InputStream}
     * @throws NullPointerException if the input parameter is null
     * @since Apache Commons IO 2.5
     */
    @SuppressWarnings("resource")
    private static BufferedInputStream buffer(final InputStream inputStream) {
        // reject null early on rather than waiting for IO operation to fail
        // not checked by BufferedInputStream
        Objects.requireNonNull(inputStream, "inputStream");
        return inputStream instanceof BufferedInputStream ? (BufferedInputStream) inputStream
                : new BufferedInputStream(inputStream);
    }

    /**
     * Checks whether in1 and in2 is equal.
     *
     * @param input1 the input1.
     * @param input2 the input2.
     * @return true if in1 and in2 is equal, else false.
     * @throws IOException if an I/O error occurs.
     * @since Apache Commons IO 2.5
     */
    @SuppressWarnings("resource")
    private static boolean contentsEquals(final InputStream input1, final InputStream input2) throws IOException {
        if (input1 == input2) {
            return true;
        }
        if (input1 == null ^ input2 == null) {
            return false;
        }
        final BufferedInputStream bufferedInput1 = buffer(input1);
        final BufferedInputStream bufferedInput2 = buffer(input2);
        int ch = bufferedInput1.read();
        while (EOF != ch) {
            final int ch2 = bufferedInput2.read();
            if (ch != ch2) {
                return false;
            }
            ch = bufferedInput1.read();
        }
        return bufferedInput2.read() == EOF;
    }

    /**
     * Logs debug messages.
     *
     * @param format See {@link String#format(String, Object...)}.
     * @param args   See {@link String#format(String, Object...)}.
     */
    private static void debug(final String format, final Object... args) {
        // TODO Find a better way to do this later.
        if (isDebug()) {
            System.out.println(String.format(format, args));
            if (args != null && args.length > 0 && args[0] instanceof Throwable) {
                ((Throwable) args[0]).printStackTrace(System.out);
            }
        }
    }

    /**
     * Extracts the specified library file to the target folder.
     *
     * @param libFolderForCurrentOS the library in commons-crypto.lib.path.
     * @param libraryFileName       the library name.
     * @param targetFolder          Target folder for the native lib. Use the value
     *                              of commons-crypto.tempdir or java.io.tmpdir.
     * @return the library file.
     */
    private static File extractLibraryFile(final String libFolderForCurrentOS, final String libraryFileName,
            final String targetFolder) {
        final String nativeLibraryFilePath = libFolderForCurrentOS + "/" + libraryFileName;

        // Attach UUID to the native library file to ensure multiple class loaders
        // can read the libcommons-crypto multiple times.
        final UUID uuid = UUID.randomUUID();
        final String extractedLibFileName = String.format("commons-crypto-%s-%s", uuid, libraryFileName);
        final File extractedLibFile = new File(targetFolder, extractedLibFileName);
        debug("Extracting '%s' to '%s'...", nativeLibraryFilePath, extractedLibFile);
        try (InputStream inputStream = NativeCodeLoader.class.getResourceAsStream(nativeLibraryFilePath)) {
            if (inputStream == null) {
                debug("Resource not found: %s", nativeLibraryFilePath);
                return null;
            }
            // Extract a native library file into the target directory
            final Path path;
            try {
                path = extractedLibFile.toPath();
                final long byteCount = Files.copy(inputStream, path, StandardCopyOption.REPLACE_EXISTING);
                if (isDebug()) {
                    debug("Extracted '%s' to '%s': %,d bytes [%s]", nativeLibraryFilePath, extractedLibFile, byteCount,
                            Files.isExecutable(path) ? "X+" : "X-");
                    final PosixFileAttributes attributes = Files.readAttributes(path, PosixFileAttributes.class);
                    if (attributes != null) {
                        debug("Attributes '%s': %s %s %s", extractedLibFile, attributes.permissions(),
                                attributes.owner(), attributes.group());
                    }
                }
            } finally {
                // Delete the extracted lib file on JVM exit.
                debug("Delete on exit: %s", extractedLibFile);
                extractedLibFile.deleteOnExit();
            }

            // Set executable (x) flag to enable Java to load the native library
            if (!extractedLibFile.setReadable(true) || !extractedLibFile.setExecutable(true)
                    || !extractedLibFile.setWritable(true, true)) {
                throw new IllegalStateException("Invalid path for library path " + extractedLibFile);
            }

            // Check whether the contents are properly copied from the resource
            // folder
            try (InputStream nativeInputStream = NativeCodeLoader.class.getResourceAsStream(nativeLibraryFilePath)) {
                try (InputStream extractedLibIn = Files.newInputStream(path)) {
                    debug("Validating '%s'...", extractedLibFile);
                    if (!contentsEquals(nativeInputStream, extractedLibIn)) {
                        throw new IllegalStateException(String.format("Failed to write a native library file %s to %s",
                                nativeLibraryFilePath, extractedLibFile));
                    }
                }
            }
            return extractedLibFile;
        } catch (final IOException e) {
            debug("Ignoring %s", e);
            return null;
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
        nativeLibraryPath = "/org/apache/commons/crypto/native/" + OsInfo.getNativeLibFolderPathForCurrentOS();
        boolean hasNativeLib = hasResource(nativeLibraryPath + "/" + nativeLibraryName);
        if (!hasNativeLib) {
            final String altName = "libcommons-crypto.jnilib";
            if (OsInfo.getOSName().equals("Mac") && hasResource(nativeLibraryPath + "/" + altName)) {
                // Fix for openjdk7 for Mac
                nativeLibraryName = altName;
                hasNativeLib = true;
            }
        }

        if (!hasNativeLib) {
            final String errorMessage = String.format("No native library is found for os.name=%s and os.arch=%s",
                    OsInfo.getOSName(), OsInfo.getArchName());
            throw new IllegalStateException(errorMessage);
        }

        // Temporary folder for the native lib. Use the value of
        // Crypto.LIB_TEMPDIR_KEY or java.io.tmpdir
        final String tempFolder = new File(
                props.getProperty(Crypto.LIB_TEMPDIR_KEY, System.getProperty("java.io.tmpdir"))).getAbsolutePath();

        // Extract and load a native library inside the jar file
        return extractLibraryFile(nativeLibraryPath, nativeLibraryName, tempFolder);
    }

    /**
     * Gets the error cause if loading failed.
     *
     * @return null, unless loading failed
     */
    static Throwable getLoadingError() {
        return loadingError;
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

    private static boolean isDebug() {
        return Boolean.getBoolean(Crypto.CONF_PREFIX + "debug");
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
     * Loads the library if possible.
     *
     * @return null if successful, otherwise the Throwable that was caught
     */
    static Throwable loadLibrary() {
        try {
            final File nativeLibFile = findNativeLibrary();
            if (nativeLibFile != null) {
                // Load extracted or specified native library.
                final String absolutePath = nativeLibFile.getAbsolutePath();
                debug("System.load('%s')", absolutePath);
                System.load(absolutePath);
            } else {
                // Load preinstalled library (in the path -Djava.library.path)
                final String libname = "commons-crypto";
                debug("System.loadLibrary('%s')", libname);
                System.loadLibrary(libname);
            }
            return null; // OK
        } catch (final Exception | UnsatisfiedLinkError t) {
            return t;
        }
    }

    /**
     * The private constructor of {@link NativeCodeLoader}.
     */
    private NativeCodeLoader() {
    }
}
