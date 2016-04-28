Apache Commons Crypto is a cryptographic library optimized with AES-NI (Advanced Encryption Standard New Instructions). It provides Java API for both cipher level and Java stream level. Developers can use it to implement high performance AES encryption/decryption with the minimum code and effort. Please note that Apache Commons Crypto doesn't implement the cryptographic algorithm such as AES directly. It wraps to Openssl or JCE which implement the algorithms.

## Features
  * Cipher API for low level cryptographic operations.
  * Java stream API (CryptoInputStream/CryptoOutputStream) for high level stream encyrption/decryption.
  * Both optimized with high performance AES encryption/decryption. (1400 MB/s - 1700 MB/s throughput in modern Xeon processors).
  * JNI-based implementation to achieve comparable performance to the native C++ version based on Openssl.
  * Portable across various operating systems (currently only Linux); Apache Commons Crypto loads the library according to your machine environment (It looks system properties, `os.name` and `os.arch`).
  * Simple usage. Add the commons-crypto-(version).jar file to your classpath.
  * [Apache License Version 2.0](http://www.apache.org/licenses/LICENSE-2.0). Free for both commercial and non-commercial use.
