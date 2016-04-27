/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 * <p/>
 * http://www.apache.org/licenses/LICENSE-2.0
 * <p/>
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.commons.crypto.benchmark.option;

import org.apache.commons.crypto.cipher.CipherTransformation;

public class StreamOption {

  private CipherTransformation transformation;
  private String cipherClazzName;
  private int bufferSize;

  private StreamOption() {
  }

  private StreamOption(int bufferSize, CipherTransformation transformation,
      String cipherClazzName) {
    this.bufferSize = bufferSize;
    this.transformation = transformation;
    this.cipherClazzName = cipherClazzName;
  }

  public CipherTransformation getTransformation() {
    return transformation;
  }

  public void setTransformation(
      CipherTransformation transformation) {
    this.transformation = transformation;
  }

  public int getBufferSize() {
    return bufferSize;
  }

  public String getCipherClazzName(){
    return cipherClazzName;
  }

  public void setBufferSize(int bufferSize) {
    this.bufferSize = bufferSize;
  }

  public String toString() {
    return "CipherTransformation is " + transformation + " " +
        "cipherClazzName is " + cipherClazzName + " bufferSize is " +
        bufferSize;
  }

  public static StreamOptionBuilder newBuilder() {
    return new StreamOptionBuilder();
  }

  public static class StreamOptionBuilder {
    private static final int DEFAULT_BUFFERSIZE = 512 * 1024;
    private CipherTransformation transformation;
    private int bufferSize = DEFAULT_BUFFERSIZE;
    private String cipherClazzName;

    public StreamOptionBuilder setBufferSize(int bufferSize) {
      this.bufferSize = bufferSize;
      return this;
    }

    public StreamOptionBuilder setCipherTransformation(
        CipherTransformation transformation) {
      this.transformation = transformation;
      return this;
    }

    public StreamOptionBuilder setCipherClazzName(String cipherClazzName){
      this.cipherClazzName = cipherClazzName;
      return this;
    }

    public StreamOption build() {
      return new StreamOption(bufferSize, transformation, cipherClazzName);
    }
  }
}
