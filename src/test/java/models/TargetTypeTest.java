package models;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class TargetTypeTest {

  @Test
  void testGetValue() {
    assertEquals((byte) 0x0, TargetType.NONE.getValue());
    assertEquals((byte) 0x1, TargetType.AUTO.getValue());
    assertEquals((byte) 0x2, TargetType.MANUAL.getValue());
    assertEquals((byte) 0x3, TargetType.AUTO_AND_MANUAL.getValue());
  }

  @Test
  void testFromByte() {
    assertEquals(TargetType.NONE, TargetType.fromByte((byte) 0x0));
    assertEquals(TargetType.AUTO, TargetType.fromByte((byte) 0x1));
    assertEquals(TargetType.MANUAL, TargetType.fromByte((byte) 0x2));
    assertEquals(TargetType.AUTO_AND_MANUAL, TargetType.fromByte((byte) 0x3));
    assertEquals(TargetType.NONE, TargetType.fromByte((byte) 0x4));
  }

  @Test
  void testHasValue() {
    assertFalse(TargetType.NONE.hasAuto());
    assertFalse(TargetType.NONE.hasManual());
    assertTrue(TargetType.AUTO.hasAuto());
    assertFalse(TargetType.AUTO.hasManual());
    assertFalse(TargetType.MANUAL.hasAuto());
    assertTrue(TargetType.MANUAL.hasManual());
    assertTrue(TargetType.AUTO_AND_MANUAL.hasAuto());
    assertTrue(TargetType.AUTO_AND_MANUAL.hasManual());
  }

  @Test
  void testSetValue() {
    final var noneType = TargetType.NONE;
    assertEquals(TargetType.NONE, noneType.setAuto(false));
    assertEquals(TargetType.AUTO, noneType.setAuto(true));
    assertEquals(TargetType.NONE, noneType.setManual(false));
    assertEquals(TargetType.MANUAL, noneType.setManual(true));

    final var autoType = TargetType.AUTO;
    assertEquals(TargetType.NONE, autoType.setAuto(false));
    assertEquals(TargetType.AUTO, autoType.setAuto(true));
    assertEquals(TargetType.AUTO, autoType.setManual(false));
    assertEquals(TargetType.AUTO_AND_MANUAL, autoType.setManual(true));

    final var manualType = TargetType.MANUAL;
    assertEquals(TargetType.MANUAL, manualType.setAuto(false));
    assertEquals(TargetType.AUTO_AND_MANUAL, manualType.setAuto(true));
    assertEquals(TargetType.NONE, manualType.setManual(false));
    assertEquals(TargetType.MANUAL, manualType.setManual(true));

    final var autoAndManualType = TargetType.AUTO_AND_MANUAL;
    assertEquals(TargetType.MANUAL, autoAndManualType.setAuto(false));
    assertEquals(TargetType.AUTO_AND_MANUAL, autoAndManualType.setAuto(true));
    assertEquals(TargetType.AUTO, autoAndManualType.setManual(false));
    assertEquals(TargetType.AUTO_AND_MANUAL, autoAndManualType.setManual(true));
  }
}
