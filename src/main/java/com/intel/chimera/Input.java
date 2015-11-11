package com.intel.chimera;

import java.io.IOException;
import java.nio.ByteBuffer;

public interface Input {
  int read(ByteBuffer dst) throws IOException;
}
