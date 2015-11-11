package com.intel.chimera;

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.channels.ReadableByteChannel;

public class ChannelInput extends StreamInput {
  private ReadableByteChannel channel;
  boolean isChannelReadSupported = true;

  public ChannelInput(
      InputStream inputStream,
      int bufferSize) {
    super(inputStream, bufferSize);
    this.channel = (ReadableByteChannel) inputStream;
  }

  public int read(ByteBuffer dst) throws IOException {
    if (isChannelReadSupported) {
      try {
        return channel.read(dst);
      } catch (UnsupportedOperationException e) {
        isChannelReadSupported = false;
        return super.read(dst);
      }
    } else {
      return super.read(dst);
    }
  }
}
