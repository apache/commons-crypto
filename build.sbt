//
// Licensed to the Apache Software Foundation (ASF) under one or more
// contributor license agreements.  See the NOTICE file distributed with
// this work for additional information regarding copyright ownership.
// The ASF licenses this file to You under the Apache License, Version 2.0
// (the "License"); you may not use this file except in compliance with
// the License.  You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

import SonatypeKeys._

sonatypeSettings

name := "chimera"

organization := "com.intel.chimera" 

organizationName := "intel.com"

description  := "chimera: A fast encryption/decryption library"

profileName := "com.intel" 

pomExtra := {
   <url>https://github.comm/intel-hadoop/chimera</url>
   <licenses>
       <license>
           <name>The Apache Software License, Version 2.0</name>
            <url>http://www.apache.org/licenses/LICENSE-2.0.txt</url>
            <distribution>repo</distribution>
        </license>
    </licenses>
    <developers>
        <developer>
            <id>dianfu</id>
            <name>Dian Fu</name>
            <email>dian.fu@intel.com</email>
            <organization>Chimera Project</organization>
            <timezone>+8</timezone>
        </developer>
    </developers>
    <issueManagement>
        <system>GitHub</system>
        <url>https://github.comm/intel-hadoop/chimera/issues/list</url>
    </issueManagement>
    <inceptionYear>2011</inceptionYear>
    <scm>
        <connection>scm:git@github.com:intel-hadoop/chimera.git</connection>
        <developerConnection>scm:git:git@github.com:intel-hadoop/chimera.git</developerConnection>
        <url>git@github.com:intel-hadoop/chimera.git</url>
    </scm>
}

scalaVersion := "2.11.1"

javacOptions in (Compile, compile) ++= Seq("-encoding", "UTF-8", "-Xlint:unchecked", "-Xlint:deprecation", "-source", "1.6", "-target", "1.6", "-g")

testOptions += Tests.Argument(TestFrameworks.JUnit, "-q", "-v")

concurrentRestrictions in Global := Seq(Tags.limit(Tags.Test, 1))

autoScalaLibrary := false

crossPaths := false

logBuffered in Test := false

incOptions := incOptions.value.withNameHashing(true)

libraryDependencies ++= Seq(
   "junit" % "junit" % "4.8.2" % "test",
   "org.codehaus.plexus" % "plexus-classworlds" % "2.4" % "test",
   "org.scalatest" % "scalatest_2.11" % "2.2.0" % "test",
   "org.osgi" % "org.osgi.core" % "4.3.0" % "provided",
   "com.novocode" % "junit-interface" % "0.10" % "test",
   "com.google.guava" % "guava" % "11.0.2" % "compile",
   "commons-logging" % "commons-logging" % "1.1.3",
   "org.slf4j" % "slf4j-api" % "1.7.10"
)
