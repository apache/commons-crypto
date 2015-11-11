package com.intel.chimera;

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;

public class StreamInput implements Input {
  private byte[] buf;
  private int bufferSize;
  InputStream in;

  public StreamInput(InputStream inputStream, int bufferSize) {
    this.in = inputStream;
    this.bufferSize = bufferSize;
  }

  public int read(ByteBuffer dst) throws IOException {
    final int remaining = dst.remaining();
    final byte[] tmp = getBuf();
    int pos = dst.position();
    int total = 0;
    while (remaining > total) {
      final int n = in.read(tmp, 0, Math.min(remaining, bufferSize));
      if (n == -1) {
        break;
      } else if (n > 0) {
        dst.put(tmp, pos, n);
        pos += n;
        total += n;
      }
    }
    return total;
  }

  private byte[] getBuf() {
    if (buf == null) {
      buf = new byte[bufferSize];
    }
    return buf;
  }
}
