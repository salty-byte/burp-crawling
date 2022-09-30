package models;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

class ColorTypeTest {

  @Test
  void testGetValue() {
    assertEquals((byte) 0x0, ColorType.DEFAULT.getValue());
    assertEquals((byte) 0x1, ColorType.RED.getValue());
    assertEquals((byte) 0x2, ColorType.ORANGE.getValue());
    assertEquals((byte) 0x3, ColorType.YELLOW.getValue());
    assertEquals((byte) 0x4, ColorType.GREEN.getValue());
    assertEquals((byte) 0x5, ColorType.BLUE.getValue());
    assertEquals((byte) 0x6, ColorType.PURPLE.getValue());
    assertEquals((byte) 0x7, ColorType.GRAY.getValue());
  }

  @Test
  void testFromByte() {
    assertEquals(ColorType.DEFAULT, ColorType.fromByte((byte) 0x0));
    assertEquals(ColorType.RED, ColorType.fromByte((byte) 0x1));
    assertEquals(ColorType.ORANGE, ColorType.fromByte((byte) 0x2));
    assertEquals(ColorType.YELLOW, ColorType.fromByte((byte) 0x3));
    assertEquals(ColorType.GREEN, ColorType.fromByte((byte) 0x4));
    assertEquals(ColorType.BLUE, ColorType.fromByte((byte) 0x5));
    assertEquals(ColorType.PURPLE, ColorType.fromByte((byte) 0x6));
    assertEquals(ColorType.GRAY, ColorType.fromByte((byte) 0x7));
  }
}
