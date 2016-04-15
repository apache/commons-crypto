Chimera [![Build Status](https://travis-ci.org/intel-hadoop/chimera.svg?branch=master)](https://travis-ci.org/intel-hadoop/chimera) is a cryptographic library optimized with AES-NI (Advanced Encryption Standard New Instructions). It provides Java API for both cipher level and Java stream level. Developers can use it to implement high performance AES encryption/decryption with the minimum code and effort. Please note that Chimera doesn't implement the cryptographic algorithm such as AES directly. It wraps to Openssl or JCE which implement the algorithms.

## Features
  * Cipher API for low level cryptographic operations.
  * Java stream API (CryptoInputStream/CryptoOutputStream) for high level stream encyrption/decryption.
  * Both optimized with high performance AES encryption/decryption. (1400 MB/s - 1700 MB/s throughput in modern Xeon processors).
  * JNI-based implementation to achieve comparable performance to the native C++ version based on Openssl.
  * Portable across various operating systems (currently only Linux); Chimera loads the library according to your machine environment (It looks system properties, `os.name` and `os.arch`). 
  * Simple usage. Add the chimera-(version).jar file to your classpath.
  * [Apache License Version 2.0](http://www.apache.org/licenses/LICENSE-2.0). Free for both commercial and non-commercial use.

## Download
  * Release version: http://central.maven.org/maven2/org/apache/commons/crypto/chimera/
  * Snapshot version (the latest beta version): https://oss.sonatype.org/content/repositories/snapshots/org/apache/commons/crypto/chimera/

### Using with Maven
  * Chimera is available from Maven's central repository:  <http://central.maven.org/maven2/org/apache/commons/crypto/chimera>

Add the following dependency to your pom.xml:

    <dependency>
      <groupId>org.apache.commons.crypto</groupId>
      <artifactId>chimera</artifactId>
      <version>0.9.0</version>
      <type>jar</type>
      <scope>compile</scope>
    </dependency>

### Using with sbt

```
libraryDependencies += "org.apache.commons.crypto" % "chimera" % "0.9.0"
```

## Usage 

```java

Properties properties = new Properties();
properties.setProperty("chimera.crypto.cipher.classes", "org.apache.commons.crypto.crypto.OpensslCipher");

Cipher cipher = Utils.getCipherInstance(CipherTransformation.AES_CTR_NOPADDING, properties);
byte[] key = new byte[16];
byte[] iv = new byte[16];
int bufferSize = 4096;
String input = "hello world!";
byte[] decryptedData = new byte[1024];
// Encrypt
ByteArrayOutputStream os = new ByteArrayOutputStream();
CryptoOutputStream cos = new CryptoOutputStream(os, cipher, bufferSize, key, iv);
cos.write(input.getBytes("UTF-8"));
cos.flush();
cos.close();

// Decrypt
CryptoInputStream cis = new CryptoInputStream(new ByteArrayInputStream(os.toByteArray()), cipher, bufferSize, key, iv);
int decryptedLen = cis.read(decryptedData, 0, 1024);

```

### Configuration
Currently, two ciphers are supported: JceCipher and OpensslCipher, you can configure which cipher to use as follows:

    $ java -Dchimera.crypto.cipher.classes=org.apache.commons.crypto.crypto.OpensslCipher Sample
    $ java -Dchimera.crypto.cipher.classes=org.apache.commons.crypto.crypto.JceCipher Sample

More detailed information about the configurations are as follows.

| Property Name | Default | Meaning         |
| --------------|---------|-------------------------|
| chimera.crypto.cipher.transformation | AES/CTR/NoPadding | The value is identical to the transformations described in the Cipher section of the Java Cryptography Architecture Standard Algorithm Name Documentation. Currently only "AES/CTR/NoPadding" algorithm is supported.|
| chimera.crypto.cipher.classes | org.apache.commons.crypto.crypto.OpensslCipher, org.apache.commons.crypto.crypto.JceCipher | Comma-separated list of cipher classes which implement cipher algorithm of "AES/CTR/NoPadding". A cipher implementation encapsulates the encryption and decryption details. The first  available implementation appearing in this list will be used. |

## Building from the source code
Building from the source code is an option when your OS platform and CPU architecture is not supported. To build Chimera, you need JDK 1.7 or higher, OpenSSL 1.0.1c or higher, etc.

    $ git clone https://github.com/intel-hadoop/chimera.git
    $ cd chimera
    $ mvn clean install

A file `target/chimera-$(version).jar` is the product additionally containing the native library built for your platform.

## Discussion
For development related discussion, please go to [dev google group](https://groups.google.com/forum/#!forum/chimera-dev).
For issues or bugs, please file tickets through [github](https://github.com/intel-hadoop/chimera/issues).
