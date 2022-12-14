/**
 * Copyright (C) 2014-2016 Open Whisper Systems
 *
 * Licensed according to the LICENSE file in this repository.
 */
package org.signal.libsignal.protocol;

public class UntrustedIdentityException extends Exception {

  private final String name;
  private final IdentityKey key;

  public UntrustedIdentityException(String name, IdentityKey key) {
    this.name = name;
    this.key  = key;
  }

  public UntrustedIdentityException(String name) {
    this.name = name;
    this.key  = null;
  }

  public IdentityKey getUntrustedIdentity() {
    return key;
  }

  public String getName() {
    return name;
  }
}
