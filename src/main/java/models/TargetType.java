package models;

import java.util.Arrays;

public enum TargetType {
  NONE((byte) 0x0),
  AUTO((byte) 0x1),
  MANUAL((byte) 0x2),
  AUTO_AND_MANUAL((byte) 0x3),
  ;

  private final byte value;

  TargetType(final byte value) {
    this.value = value;
  }

  public byte getValue() {
    return value;
  }

  public boolean hasAuto() {
    return (value & 0x1) == 1;
  }

  public boolean hasManual() {
    return ((value >> 1) & 0x1) == 1;
  }

  public TargetType setAuto(final boolean hasAuto) {
    final var nextValue = (byte) ((value & 0x2) | (hasAuto ? 0x1 : 0x0));
    return fromByte(nextValue);
  }


  public TargetType setManual(final boolean hasManual) {
    final var nextValue = (byte) ((hasManual ? 0x2 : 0x0) | (value & 0x1));
    return fromByte(nextValue);
  }

  public static TargetType fromByte(final byte value) {
    final var result = Arrays.stream(TargetType.values())
        .filter(e -> e.value == value)
        .findAny();
    if (result.isEmpty()) {
      return NONE;
    }
    return result.get();
  }
}
