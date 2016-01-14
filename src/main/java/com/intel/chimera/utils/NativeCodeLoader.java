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
package com.intel.chimera.utils;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.util.Properties;
import java.util.UUID;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;


/**
 * A helper to load the native code i.e. libchimera.so.
 * This handles the fallback to either the bundled libchimera-Linux-i386-32.so
 * or the default java implementations where appropriate.
 */
public class NativeCodeLoader {

  private static final Log LOG =
    LogFactory.getLog(NativeCodeLoader.class);
  
  private static boolean nativeCodeLoaded = false;
  
  static {
    // Try to load native library and set fallback flag appropriately
    if(LOG.isDebugEnabled()) {
      LOG.debug("Trying to load the custom-built native-chimera library...");
    }

    try {
      File nativeLibFile = findNativeLibrary();
      if (nativeLibFile != null) {
        // Load extracted or specified native library.
        System.load(nativeLibFile.getAbsolutePath());
      } else {
        // Load preinstalled library (in the path -Djava.library.path)
        System.loadLibrary("chimera");
      }
      LOG.debug("Loaded the native library");
      nativeCodeLoaded = true;
    } catch (Throwable t) {
      // Ignore failure to load
      if(LOG.isDebugEnabled()) {
        LOG.debug("Failed to load native library with error: " + t);
        LOG.debug("java.library.path=" +
            System.getProperty("java.library.path"));
      }
    }

    if (!nativeCodeLoaded) {
      LOG.warn("Unable to load native library for the platform... " +
               "using builtin-java classes where applicable");
    }
  }

  static File findNativeLibrary() {
    // Try to load the library in chimera.lib.path */
    String nativeLibraryPath = Utils
        .getLibPath();
    String nativeLibraryName = Utils
        .getLibName();

    // Resolve the library file name with a suffix (e.g., dll, .so, etc.)
    if (nativeLibraryName == null)
      nativeLibraryName = System.mapLibraryName("chimera");

    if (nativeLibraryPath != null) {
      File nativeLib = new File(nativeLibraryPath,
          nativeLibraryName);
      if (nativeLib.exists())
        return nativeLib;
    }

    // Load an OS-dependent native library inside a jar file
    nativeLibraryPath = "/com/intel/chimera/native/"
        + OSInfo.getNativeLibFolderPathForCurrentOS();
    boolean hasNativeLib = hasResource(nativeLibraryPath + "/"
        + nativeLibraryName);
    if(!hasNativeLib) {
      if (OSInfo.getOSName().equals("Mac")) {
        // Fix for openjdk7 for Mac
        String altName = "libchimera.jnilib";
        if (hasResource(nativeLibraryPath + "/" + altName)) {
          nativeLibraryName = altName;
          hasNativeLib = true;
        }
      }
    }

    if (!hasNativeLib) {
      String errorMessage = String.format(
          "no native library is found for os.name=%s and os.arch=%s",
          OSInfo.getOSName(), OSInfo.getArchName());
      throw new RuntimeException(errorMessage);
    }

    // Temporary folder for the native lib. Use the value of
    // chimera.tempdir or java.io.tmpdir
    String tempFolder = new File(Utils.getTmpDir())
        .getAbsolutePath();

    // Extract and load a native library inside the jar file
    return extractLibraryFile(nativeLibraryPath,
        nativeLibraryName, tempFolder);
  }

  /**
   * Extract the specified library file to the target folder
   * 
   * @param libFolderForCurrentOS
   * @param libraryFileName
   * @param targetFolder
   * @return
   */
  private static File extractLibraryFile(String libFolderForCurrentOS,
      String libraryFileName, String targetFolder) {
    String nativeLibraryFilePath = libFolderForCurrentOS + "/"
        + libraryFileName;

    // Attach UUID to the native library file to ensure multiple class loaders
    // can read the libchimera multiple times.
    String uuid = UUID.randomUUID().toString();
    String extractedLibFileName = String.format("chimera-%s-%s-%s", getVersion(), uuid,
        libraryFileName);
    File extractedLibFile = new File(targetFolder, extractedLibFileName);

    InputStream reader = null;
    try {
      // Extract a native library file into the target directory
      reader = NativeCodeLoader.class.getResourceAsStream(nativeLibraryFilePath);
      FileOutputStream writer = new FileOutputStream(extractedLibFile);
      try {
        byte[] buffer = new byte[8192];
        int bytesRead;
        while ((bytesRead = reader.read(buffer)) != -1) {
          writer.write(buffer, 0, bytesRead);
        }
      } finally {
        // Delete the extracted lib file on JVM exit.
        extractedLibFile.deleteOnExit();

        if (writer != null){
          writer.close();
        }

        if (reader != null) {
          reader.close();
          reader = null;
        }
      }

      // Set executable (x) flag to enable Java to load the native library
      if (!extractedLibFile.setReadable(true) || !extractedLibFile.setExecutable(true)
          || !extractedLibFile.setWritable(true, true)) {
        throw new RuntimeException("Invalid path for library path");
      }

      // Check whether the contents are properly copied from the resource folder
      {
        InputStream nativeIn = null;
        InputStream extractedLibIn = null;
        try {
          nativeIn =
              NativeCodeLoader.class.getResourceAsStream(nativeLibraryFilePath);
          extractedLibIn = new FileInputStream(extractedLibFile);
          if (!contentsEquals(nativeIn, extractedLibIn))
            throw new RuntimeException(String.format(
                    "Failed to write a native library file at %s",
                    extractedLibFile));
        } finally {
          if (nativeIn != null)
            nativeIn.close();
          if (extractedLibIn != null)
            extractedLibIn.close();
        }
      }

      return new File(targetFolder, extractedLibFileName);
    } catch (IOException e) {
      e.printStackTrace(System.err);
      return null;
    } finally{
      if(reader != null){
        try {
          reader.close();
        } catch (IOException e) {
          e.printStackTrace();
        }
      }
    }
  }

  /**
   * Get the version by reading pom.properties embedded in jar.
   * This version data is used as a suffix of a dll file extracted from the
   * jar.
   * 
   * @return the version string
   */
  public static String getVersion() {
    URL versionFile = NativeCodeLoader.class
        .getResource("/META-INF/maven/com.intel.chimera/chimera/pom.properties");
    if (versionFile == null)
      versionFile = NativeCodeLoader.class
          .getResource("/com/intel/chimera/VERSION");

    String version = "unknown";
    try {
      if (versionFile != null) {
        Properties versionData = new Properties();
        versionData.load(versionFile.openStream());
        version = versionData.getProperty("version", version);
        if (version.equals("unknown"))
          version = versionData.getProperty("VERSION", version);
        version = version.trim().replaceAll("[^0-9M\\.]", "");
      }
    } catch (IOException e) {
      System.err.println(e);
    }
    return version;
  }

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
      int ch2 = in2.read();
      if (ch != ch2)
        return false;
      ch = in1.read();
    }
    int ch2 = in2.read();
    return ch2 == -1;
  }

  private static boolean hasResource(String path) {
    return NativeCodeLoader.class.getResource(path) != null;
  }

  /**
   * Check if native code is loaded for this platform.
   * 
   * @return <code>true</code> if native is loaded, 
   *         else <code>false</code>
   */
  public static boolean isNativeCodeLoaded() {
    return nativeCodeLoaded;
  }
}
