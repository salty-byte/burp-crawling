package models;

import java.awt.Color;
import java.util.Arrays;

public enum ColorType {
  DEFAULT((byte) 0x0, "デフォルト", null, null),
  RED((byte) 0x1, "赤", new Color(255, 128, 114), Color.BLACK),
  ORANGE((byte) 0x2, "橙", new Color(255, 201, 102), Color.BLACK),
  YELLOW((byte) 0x3, "黄", new Color(255, 255, 102), Color.BLACK),
  GREEN((byte) 0x4, "緑", new Color(128, 255, 128), Color.BLACK),
  BLUE((byte) 0x5, "青", new Color(112, 140, 224), Color.BLACK),
  PURPLE((byte) 0x6, "紫", new Color(255, 179, 242), Color.BLACK),
  GRAY((byte) 0x7, "灰", new Color(180, 180, 180), Color.BLACK),
  ;

  private final byte value;
  private final String displayName;
  private final Color background;
  private final Color foreground;

  ColorType(final byte value, final String displayName, final Color background,
      final Color foreground) {
    this.value = value;
    this.displayName = displayName;
    this.background = background;
    this.foreground = foreground;
  }

  public byte getValue() {
    return value;
  }

  public String getDisplayName() {
    return displayName;
  }

  public Color getBackground() {
    return background;
  }

  public Color getForeground() {
    return foreground;
  }

  public Color getSelectionBackground() {
    return background == null ? null : background.darker();
  }

  public Color getSelectionForeground() {
    return foreground;
  }

  public static ColorType fromByte(final byte value) {
    final var result = Arrays.stream(ColorType.values())
        .filter(e -> e.value == value)
        .findAny();
    if (result.isEmpty()) {
      return DEFAULT;
    }
    return result.get();
  }
}
