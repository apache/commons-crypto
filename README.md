<!---
 Licensed to the Apache Software Foundation (ASF) under one or more
 contributor license agreements.  See the NOTICE file distributed with
 this work for additional information regarding copyright ownership.
 The ASF licenses this file to You under the Apache License, Version 2.0
 (the "License"); you may not use this file except in compliance with
 the License.  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
-->
<!---
 +======================================================================+
 |****                                                              ****|
 |****      THIS FILE IS GENERATED BY THE COMMONS BUILD PLUGIN      ****|
 |****                    DO NOT EDIT DIRECTLY                      ****|
 |****                                                              ****|
 +======================================================================+
 | TEMPLATE FILE: readme-md-template.md                                 |
 | commons-build-plugin/trunk/src/main/resources/commons-xdoc-templates |
 +======================================================================+
 |                                                                      |
 | 1) Re-generate using: mvn commons-build:readme-md                    |
 |                                                                      |
 | 2) Set the following properties in the component's pom:              |
 |    - commons.componentid (required, alphabetic, lower case)          |
 |    - commons.release.version (required)                              |
 |                                                                      |
 | 3) Example Properties                                                |
 |                                                                      |
 |  <properties>                                                        |
 |    <commons.componentid>math</commons.componentid>                   |
 |    <commons.release.version>1.2</commons.release.version>            |
 |  </properties>                                                       |
 |                                                                      |
 +======================================================================+
--->
Apache Commons Crypto
===================

[![GitHub Actions Status](https://github.com/apache/commons-crypto/workflows/Java%20CI/badge.svg)](https://github.com/apache/commons-crypto/actions)
[![Coverage Status](https://codecov.io/gh/apache/commons-crypto/branch/master/graph/badge.svg)](https://app.codecov.io/gh/apache/commons-crypto)
[![Maven Central](https://maven-badges.herokuapp.com/maven-central/org.apache.commons/commons-crypto/badge.svg?gav=true)](https://maven-badges.herokuapp.com/maven-central/org.apache.commons/commons-crypto/?gav=true)
[![Javadocs](https://javadoc.io/badge/org.apache.commons/commons-crypto/1.2.0.svg)](https://javadoc.io/doc/org.apache.commons/commons-crypto/1.2.0)
[![CodeQL](https://github.com/apache/commons-crypto/workflows/CodeQL/badge.svg)](https://github.com/apache/commons-crypto/actions/workflows/codeql-analysis.yml?query=workflow%3ACodeQL)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/apache/commons-text/badge)](https://api.securityscorecards.dev/projects/github.com/apache/commons-text)

Apache Commons Crypto is a cryptographic library optimized with AES-NI (Advanced Encryption
Standard New Instructions). It provides Java API for both cipher level and Java stream level.
Developers can use it to implement high performance AES encryption/decryption with the minimum
code and effort. Please note that Crypto doesn't implement the cryptographic algorithm such as
AES directly. It wraps to OpenSSL or JCE which implement the algorithms.

Features
--------

1. Cipher API for low level cryptographic operations.
2. Java stream API (CryptoInputStream/CryptoOutputStream) for high level stream encryption/decryption.
3. Both optimized with high performance AES encryption/decryption. (1400 MB/s - 1700 MB/s throughput in modern Xeon processors).
4. JNI-based implementation to achieve comparable performance to the native C/C++ version based on OpenSsl.
5. Portable across various operating systems (currently only Linux/MacOSX/Windows);
   Apache Commons Crypto loads the library according to your machine environment (it checks system properties, `os.name` and `os.arch`).
6. Simple usage. Add the commons-crypto-(version).jar file to your classpath.


Export restrictions
-------------------

This distribution includes cryptographic software.
The country in which you currently reside may have restrictions
on the import, possession, use, and/or re-export to another country,
of encryption software. BEFORE using any encryption software,
please check your country's laws, regulations and policies
concerning the import, possession, or use, and re-export of
encryption software, to see if this is permitted.
See <http://www.wassenaar.org/> for more information.

The U.S. Government Department of Commerce, Bureau of Industry and Security (BIS),
has classified this software as Export Commodity Control Number (ECCN) 5D002.C.1,
which includes information security software using or performing
cryptographic functions with asymmetric algorithms.
The form and manner of this Apache Software Foundation distribution makes
it eligible for export under the License Exception
ENC Technology Software Unrestricted (TSU) exception
(see the BIS Export Administration Regulations, Section 740.13)
for both object code and source code.

The following provides more details on the included cryptographic software:

* Commons Crypto use [Java Cryptography Extension](http://docs.oracle.com/javase/8/docs/technotes/guides/security/crypto/CryptoSpec.html) provided by Java
* Commons Crypto link to and use [OpenSSL](https://www.openssl.org/) ciphers

Documentation
-------------

More information can be found on the [Apache Commons Crypto homepage](https://commons.apache.org/proper/commons-crypto).
The [Javadoc](https://commons.apache.org/proper/commons-crypto/apidocs) can be browsed.
Questions related to the usage of Apache Commons Crypto should be posted to the [user mailing list][ml].

Where can I get the latest release?
-----------------------------------
You can download source and binaries from our [download page](https://commons.apache.org/proper/commons-crypto/download_crypto.cgi).

Alternatively you can pull it from the central Maven repositories:

```xml
<dependency>
  <groupId>org.apache.commons</groupId>
  <artifactId>commons-crypto</artifactId>
  <version>1.2.0</version>
</dependency>
```

Contributing
------------

We accept Pull Requests via GitHub. The [developer mailing list](https://commons.apache.org/mail-lists.html) is the main channel of communication for contributors.
There are some guidelines which will make applying PRs easier for us:
+ No tabs! Please use spaces for indentation.
+ Respect the code style.
+ Create minimal diffs - disable on save actions like reformat source code or organize imports. If you feel the source code should be reformatted create a separate PR for this change.
+ Provide JUnit tests for your changes and make sure your changes don't break any existing tests by running ```mvn```.

If you plan to contribute on a regular basis, please consider filing a [contributor license agreement](https://www.apache.org/licenses/#clas).
You can learn more about contributing via GitHub in our [contribution guidelines](CONTRIBUTING.md).

License
-------
This code is under the [Apache Licence v2](https://www.apache.org/licenses/LICENSE-2.0).

See the `NOTICE.txt` file for required notices and attributions.

Donations
---------
You like Apache Commons Crypto? Then [donate back to the ASF](https://www.apache.org/foundation/contributing.html) to support the development.

Additional Resources
--------------------

+ [Apache Commons Homepage](https://commons.apache.org/)
+ [Apache Issue Tracker (JIRA)](https://issues.apache.org/jira/browse/CRYPTO)
+ [Apache Commons Slack Channel](https://the-asf.slack.com/archives/C60NVB8AD)
+ [Apache Commons Twitter Account](https://twitter.com/ApacheCommons)
+ `#apache-commons` IRC channel on `irc.freenode.org`

Apache Commons Components
-------------------------

| Component | GitHub Repository | Apache Homepage |
| --------- | ----------------- | ----------------|
| Apache Commons BCEL | [commons-bcel](https://github.com/apache/commons-bcel) | [commons-bcel](https://commons.apache.org/proper/commons-bcel) |
| Apache Commons Beanutils | [commons-beanutils](https://github.com/apache/commons-beanutils) | [commons-beanutils](https://commons.apache.org/proper/commons-beanutils) |
| Apache Commons BSF | [commons-bsf](https://github.com/apache/commons-bsf) | [commons-bsf](https://commons.apache.org/proper/commons-bsf) |
| Apache Commons Build-plugin | [commons-build-plugin](https://github.com/apache/commons-build-plugin) | [commons-build-plugin](https://commons.apache.org/proper/commons-build-plugin) |
| Apache Commons Chain | [commons-chain](https://github.com/apache/commons-chain) | [commons-chain](https://commons.apache.org/proper/commons-chain) |
| Apache Commons CLI | [commons-cli](https://github.com/apache/commons-cli) | [commons-cli](https://commons.apache.org/proper/commons-cli) |
| Apache Commons Codec | [commons-codec](https://github.com/apache/commons-codec) | [commons-codec](https://commons.apache.org/proper/commons-codec) |
| Apache Commons Collections | [commons-collections](https://github.com/apache/commons-collections) | [commons-collections](https://commons.apache.org/proper/commons-collections) |
| Apache Commons Compress | [commons-compress](https://github.com/apache/commons-compress) | [commons-compress](https://commons.apache.org/proper/commons-compress) |
| Apache Commons Configuration | [commons-configuration](https://github.com/apache/commons-configuration) | [commons-configuration](https://commons.apache.org/proper/commons-configuration) |
| Apache Commons Crypto | [commons-crypto](https://github.com/apache/commons-crypto) | [commons-crypto](https://commons.apache.org/proper/commons-crypto) |
| Apache Commons CSV | [commons-csv](https://github.com/apache/commons-csv) | [commons-csv](https://commons.apache.org/proper/commons-csv) |
| Apache Commons Daemon | [commons-daemon](https://github.com/apache/commons-daemon) | [commons-daemon](https://commons.apache.org/proper/commons-daemon) |
| Apache Commons DBCP | [commons-dbcp](https://github.com/apache/commons-dbcp) | [commons-dbcp](https://commons.apache.org/proper/commons-dbcp) |
| Apache Commons Dbutils | [commons-dbutils](https://github.com/apache/commons-dbutils) | [commons-dbutils](https://commons.apache.org/proper/commons-dbutils) |
| Apache Commons Digester | [commons-digester](https://github.com/apache/commons-digester) | [commons-digester](https://commons.apache.org/proper/commons-digester) |
| Apache Commons Email | [commons-email](https://github.com/apache/commons-email) | [commons-email](https://commons.apache.org/proper/commons-email) |
| Apache Commons Exec | [commons-exec](https://github.com/apache/commons-exec) | [commons-exec](https://commons.apache.org/proper/commons-exec) |
| Apache Commons Fileupload | [commons-fileupload](https://github.com/apache/commons-fileupload) | [commons-fileupload](https://commons.apache.org/proper/commons-fileupload) |
| Apache Commons Functor | [commons-functor](https://github.com/apache/commons-functor) | [commons-functor](https://commons.apache.org/proper/commons-functor) |
| Apache Commons Geometry | [commons-geometry](https://github.com/apache/commons-geometry) | [commons-geometry](https://commons.apache.org/proper/commons-geometry) |
| Apache Commons Graph | [commons-graph](https://github.com/apache/commons-graph) | [commons-graph](https://commons.apache.org/proper/commons-graph) |
| Apache Commons Imaging | [commons-imaging](https://github.com/apache/commons-imaging) | [commons-imaging](https://commons.apache.org/proper/commons-imaging) |
| Apache Commons IO | [commons-io](https://github.com/apache/commons-io) | [commons-io](https://commons.apache.org/proper/commons-io) |
| Apache Commons JCI | [commons-jci](https://github.com/apache/commons-jci) | [commons-jci](https://commons.apache.org/proper/commons-jci) |
| Apache Commons JCS | [commons-jcs](https://github.com/apache/commons-jcs) | [commons-jcs](https://commons.apache.org/proper/commons-jcs) |
| Apache Commons Jelly | [commons-jelly](https://github.com/apache/commons-jelly) | [commons-jelly](https://commons.apache.org/proper/commons-jelly) |
| Apache Commons Jexl | [commons-jexl](https://github.com/apache/commons-jexl) | [commons-jexl](https://commons.apache.org/proper/commons-jexl) |
| Apache Commons Jxpath | [commons-jxpath](https://github.com/apache/commons-jxpath) | [commons-jxpath](https://commons.apache.org/proper/commons-jxpath) |
| Apache Commons Lang | [commons-lang](https://github.com/apache/commons-lang) | [commons-lang](https://commons.apache.org/proper/commons-lang) |
| Apache Commons Logging | [commons-logging](https://github.com/apache/commons-logging) | [commons-logging](https://commons.apache.org/proper/commons-logging) |
| Apache Commons Math | [commons-math](https://github.com/apache/commons-math) | [commons-math](https://commons.apache.org/proper/commons-math) |
| Apache Commons Net | [commons-net](https://github.com/apache/commons-net) | [commons-net](https://commons.apache.org/proper/commons-net) |
| Apache Commons Numbers | [commons-numbers](https://github.com/apache/commons-numbers) | [commons-numbers](https://commons.apache.org/proper/commons-numbers) |
| Apache Commons Parent | [commons-parent](https://github.com/apache/commons-parent) | [commons-parent](https://commons.apache.org/proper/commons-parent) |
| Apache Commons Pool | [commons-pool](https://github.com/apache/commons-pool) | [commons-pool](https://commons.apache.org/proper/commons-pool) |
| Apache Commons Proxy | [commons-proxy](https://github.com/apache/commons-proxy) | [commons-proxy](https://commons.apache.org/proper/commons-proxy) |
| Apache Commons RDF | [commons-rdf](https://github.com/apache/commons-rdf) | [commons-rdf](https://commons.apache.org/proper/commons-rdf) |
| Apache Commons Release-plugin | [commons-release-plugin](https://github.com/apache/commons-release-plugin) | [commons-release-plugin](https://commons.apache.org/proper/commons-release-plugin) |
| Apache Commons Rng | [commons-rng](https://github.com/apache/commons-rng) | [commons-rng](https://commons.apache.org/proper/commons-rng) |
| Apache Commons Scxml | [commons-scxml](https://github.com/apache/commons-scxml) | [commons-scxml](https://commons.apache.org/proper/commons-scxml) |
| Apache Commons Signing | [commons-signing](https://github.com/apache/commons-signing) | [commons-signing](https://commons.apache.org/proper/commons-signing) |
| Apache Commons Skin | [commons-skin](https://github.com/apache/commons-skin) | [commons-skin](https://commons.apache.org/proper/commons-skin) |
| Apache Commons Statistics | [commons-statistics](https://github.com/apache/commons-statistics) | [commons-statistics](https://commons.apache.org/proper/commons-statistics) |
| Apache Commons Testing | [commons-testing](https://github.com/apache/commons-testing) | [commons-testing](https://commons.apache.org/proper/commons-testing) |
| Apache Commons Text | [commons-text](https://github.com/apache/commons-text) | [commons-text](https://commons.apache.org/proper/commons-text) |
| Apache Commons Validator | [commons-validator](https://github.com/apache/commons-validator) | [commons-validator](https://commons.apache.org/proper/commons-validator) |
| Apache Commons VFS | [commons-vfs](https://github.com/apache/commons-vfs) | [commons-vfs](https://commons.apache.org/proper/commons-vfs) |
| Apache Commons Weaver | [commons-weaver](https://github.com/apache/commons-weaver) | [commons-weaver](https://commons.apache.org/proper/commons-weaver) |
