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

package org.apache.commons.crypto.jna;

import java.nio.ByteBuffer;

import com.sun.jna.Function;
import com.sun.jna.NativeLibrary;
import com.sun.jna.NativeLong;
import com.sun.jna.ptr.PointerByReference;

class OpenSslNativeJna {

  static final int OPENSSL_INIT_ENGINE_RDRAND = 0x00000200;

  static final int OOSL_JNA_ENCRYPT_MODE = 1;
  static final int OOSL_JNA_DECRYPT_MODE = 0;

  static final boolean INIT_OK;

  static final Throwable INIT_ERROR;

  public static final long VERSION;
  public static final long VERSION_1_0_X = 0x10000000;
  public static final long VERSION_1_1_X = 0x10100000;

  static {
    NativeLibrary crypto = NativeLibrary.getInstance("crypto");
    Function version = null;
    try {
      version = crypto.getFunction("SSLeay");
      } catch (UnsatisfiedLinkError e) {
        // Swallow the Error.
      }

      if (version == null) {
        VERSION = VERSION_1_1_X;
      } else {
        VERSION = VERSION_1_0_X;
      }

      if (VERSION == VERSION_1_1_X) {
        INIT_OK = OpenSsl110NativeJna.INIT_OK;
      } else if (VERSION == VERSION_1_0_X) {
        INIT_OK = OpenSsl102NativeJna.INIT_OK;
      } else {
        INIT_OK = false;
      }

      if (INIT_OK) {
        INIT_ERROR = null;
      } else if (VERSION == VERSION_1_1_X) {
        INIT_ERROR = OpenSsl110NativeJna.INIT_ERROR;
      } else if (VERSION == VERSION_1_0_X) {
        INIT_ERROR = OpenSsl102NativeJna.INIT_ERROR;
      }  else {
        INIT_ERROR = null;
      }
    }

  public static PointerByReference ENGINE_by_id(String string) {
    if (VERSION == VERSION_1_1_X) {
      return OpenSsl110NativeJna.ENGINE_by_id(string);
    } else if (VERSION == VERSION_1_0_X) {
      return OpenSsl102NativeJna.ENGINE_by_id(string);
    } else {
      return null;
    }
  }

  public static void ENGINE_finish(PointerByReference rdrandEngine) {
    if (VERSION == VERSION_1_1_X) {
      OpenSsl110NativeJna.ENGINE_finish(rdrandEngine);
      } else if (VERSION == VERSION_1_0_X) {
        OpenSsl102NativeJna.ENGINE_finish(rdrandEngine);
      } else {
        return;
      }
  }

  public static void ENGINE_free(PointerByReference rdrandEngine) {
    if (VERSION == VERSION_1_1_X) {
      OpenSsl110NativeJna.ENGINE_free(rdrandEngine);
    } else if (VERSION == VERSION_1_0_X) {
      OpenSsl102NativeJna.ENGINE_free(rdrandEngine);
    } else {
      return;
    }
  }

  public static int ENGINE_init(PointerByReference rdrandEngine) {
    if (VERSION == VERSION_1_1_X) {
      return OpenSsl110NativeJna.ENGINE_init(rdrandEngine);
    } else if (VERSION == VERSION_1_0_X) {
      return OpenSsl102NativeJna.ENGINE_init(rdrandEngine);
    } else {
      return 0;
    }
  }

  public static int ENGINE_set_default(PointerByReference rdrandEngine, int eNGINE_METHOD_RAND) {
    if (VERSION == VERSION_1_1_X) {
      return OpenSsl110NativeJna.ENGINE_set_default(rdrandEngine, eNGINE_METHOD_RAND);
    } else if (VERSION == VERSION_1_0_X) {
      return OpenSsl102NativeJna.ENGINE_set_default(rdrandEngine, eNGINE_METHOD_RAND);
    } else {
      return 0;
    }
  }

  public static String ERR_error_string(NativeLong err, Object object) {
    if (VERSION == VERSION_1_1_X) {
      return OpenSsl110NativeJna.ERR_error_string(err, null);
    } else if (VERSION == VERSION_1_0_X) {
      return OpenSsl102NativeJna.ERR_error_string(err, null);
    } else {
      return null;
    }
  }

  public static NativeLong ERR_peek_error() {
    if (VERSION == VERSION_1_1_X) {
      return OpenSsl110NativeJna.ERR_peek_error();
    } else if (VERSION == VERSION_1_0_X) {
      return OpenSsl102NativeJna.ERR_peek_error();
    } else {
      return null;
    }
  }

  public static PointerByReference EVP_aes_128_cbc() {
    if (VERSION == VERSION_1_1_X) {
      return OpenSsl110NativeJna.EVP_aes_128_cbc();
    } else if (VERSION == VERSION_1_0_X) {
      return OpenSsl102NativeJna.EVP_aes_128_cbc();
    } else {
      return null;
    }
  }

  public static PointerByReference EVP_aes_128_ctr() {
    if (VERSION == VERSION_1_1_X) {
      return OpenSsl110NativeJna.EVP_aes_128_ctr();
    } else if (VERSION == VERSION_1_0_X) {
      return OpenSsl102NativeJna.EVP_aes_128_ctr();
    } else {
      return null;
    }
  }

  public static PointerByReference EVP_aes_192_cbc() {
    if (VERSION == VERSION_1_1_X) {
      return OpenSsl110NativeJna.EVP_aes_192_cbc();
    } else if (VERSION == VERSION_1_0_X) {
      return OpenSsl102NativeJna.EVP_aes_192_cbc();
    } else {
      return null;
    }
 }

  public static PointerByReference EVP_aes_192_ctr() {
    if (VERSION == VERSION_1_1_X) {
      return OpenSsl110NativeJna.EVP_aes_192_ctr();
    } else if (VERSION == VERSION_1_0_X) {
      return OpenSsl102NativeJna.EVP_aes_192_ctr();
    } else {
      return null;
    }
  }

  public static PointerByReference EVP_aes_256_cbc() {
    if (VERSION == VERSION_1_1_X) {
      return OpenSsl110NativeJna.EVP_aes_256_cbc();
    } else if (VERSION == VERSION_1_0_X) {
      return OpenSsl102NativeJna.EVP_aes_256_cbc();
    } else {
      return null;
    }
  }

  public static PointerByReference EVP_aes_256_ctr() {
    if (VERSION == VERSION_1_1_X) {
      return OpenSsl110NativeJna.EVP_aes_256_ctr();
    } else if (VERSION == VERSION_1_0_X) {
      return OpenSsl102NativeJna.EVP_aes_256_ctr();
    } else {
      return null;
    }
  }

  public static void EVP_CIPHER_CTX_free(PointerByReference context) {
    if (VERSION == VERSION_1_1_X) {
      OpenSsl110NativeJna.EVP_CIPHER_CTX_free(context);
    } else if (VERSION == VERSION_1_0_X) {
      OpenSsl102NativeJna.EVP_CIPHER_CTX_free(context);
    } else {
      return;
    }
  }

  public static PointerByReference EVP_CIPHER_CTX_new() {
    if (VERSION == VERSION_1_1_X) {
      return OpenSsl110NativeJna.EVP_CIPHER_CTX_new();
    } else if (VERSION == VERSION_1_0_X) {
      return OpenSsl102NativeJna.EVP_CIPHER_CTX_new();
    } else {
      return null;
    }
  }

  public static void EVP_CIPHER_CTX_set_padding(PointerByReference context, int padding) {
    if (VERSION == VERSION_1_1_X) {
      OpenSsl110NativeJna.EVP_CIPHER_CTX_set_padding(context, padding);
    } else if (VERSION == VERSION_1_0_X) {
      OpenSsl102NativeJna.EVP_CIPHER_CTX_set_padding(context, padding);
    } else {
      return;
    }
  }

  public static int EVP_CipherFinal_ex(PointerByReference context, ByteBuffer outBuffer, int[] outlen) {
    if (VERSION == VERSION_1_1_X) {
      return OpenSsl110NativeJna.EVP_CipherFinal_ex(context, outBuffer, outlen);
    } else if (VERSION == VERSION_1_0_X) {
      return OpenSsl102NativeJna.EVP_CipherFinal_ex(context, outBuffer, outlen);
    } else {
      return 0;
    }
  }

  public static int EVP_CipherInit_ex(PointerByReference context, PointerByReference algo, Object object,
      byte[] encoded, byte[] iv, int cipherMode) {
    if (VERSION == VERSION_1_1_X) {
      return OpenSsl110NativeJna.EVP_CipherInit_ex(context, algo, null, encoded, iv, cipherMode);
    } else if (VERSION == VERSION_1_0_X) {
      return OpenSsl102NativeJna.EVP_CipherInit_ex(context, algo, null, encoded, iv, cipherMode);
    } else {
      return 0;
    }
  }

  public static int EVP_CipherUpdate(PointerByReference context, ByteBuffer outBuffer, int[] outlen,
      ByteBuffer inBuffer, int remaining) {
    if (VERSION == VERSION_1_1_X) {
      return OpenSsl110NativeJna.EVP_CipherUpdate(context, outBuffer, outlen, inBuffer, remaining);
    } else if (VERSION == VERSION_1_0_X) {
      return OpenSsl102NativeJna.EVP_CipherUpdate(context, outBuffer, outlen, inBuffer, remaining);
    } else {
      return 0;
    }
  }

  public static int RAND_bytes(ByteBuffer buf, int length) {
    if (VERSION == VERSION_1_1_X) {
      return OpenSsl110NativeJna.RAND_bytes(buf, length);
    } else if (VERSION == VERSION_1_0_X) {
      return OpenSsl102NativeJna.RAND_bytes(buf, length);
    } else {
      return 0;
    }
  }

  public static PointerByReference RAND_get_rand_method() {
    if (VERSION == VERSION_1_1_X) {
      return OpenSsl110NativeJna.RAND_get_rand_method();
    } else if (VERSION == VERSION_1_0_X) {
      return OpenSsl102NativeJna.RAND_get_rand_method();
    } else {
      return null;
    }
  }

  public static PointerByReference RAND_SSLeay() {
    if (VERSION == VERSION_1_1_X) {
      return null;
    } else if (VERSION == VERSION_1_0_X) {
      return OpenSsl102NativeJna.RAND_SSLeay();
    } else {
      return null;
    }
  }

  public static String OpenSSLVersion(int i) {
    if (VERSION == VERSION_1_1_X) {
      return OpenSsl110NativeJna.OpenSSL_version(i);
    } else if (VERSION == VERSION_1_0_X) {
      return OpenSsl102NativeJna.SSLeay_version(i);
    } else {
      return null;
    }
  }

  public static void ENGINE_load_rdrand() {
    if (VERSION == VERSION_1_1_X) {
      return;
    } else if (VERSION == VERSION_1_0_X) {
      OpenSsl102NativeJna.ENGINE_load_rdrand();
    } else {
      return;
    }
  }

  public static void ENGINE_cleanup() {
    if (VERSION == VERSION_1_1_X) {
      return;
    } else if (VERSION == VERSION_1_0_X) {
      OpenSsl102NativeJna.ENGINE_cleanup();
    } else {
      return;
    }
  }

  public static void EVP_CIPHER_CTX_cleanup(PointerByReference context) {
    if (VERSION == VERSION_1_1_X) {
      return;
    } else if (VERSION == VERSION_1_0_X) {
      OpenSsl102NativeJna.EVP_CIPHER_CTX_cleanup(context);
    } else {
      return;
    }
  }
}