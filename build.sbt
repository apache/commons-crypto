import SonatypeKeys._

sonatypeSettings

name := "chimera"

organization := "org.chimera" 

organizationName := "chimera.org"

description  := "chimera: A fast encryption/decryption library"

profileName := "org.chimera" 

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

javacOptions in (Compile, compile) ++= Seq("-encoding", "UTF-8", "-Xlint:unchecked", "-Xlint:deprecation", "-source", "1.6", "-target", "1.6")

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
