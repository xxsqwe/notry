/**
 * Copyright (C) 2014-2016 Open Whisper Systems
 *
 * Licensed according to the LICENSE file in this repository.
 */
package org.signal.libsignal.protocol;

public class LegacyMessageException extends Exception {
  public LegacyMessageException(String s) {
    super(s);
  }
}
