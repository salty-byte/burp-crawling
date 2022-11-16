package models;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class LogEntryKeyTest {

  @Test
  void testCount() {
    assertEquals(17, LogEntryKey.values().length);
  }

  @Test
  void testGetClassification() {
    assertEquals(Integer.class, LogEntryKey.NUMBER.getClassification());
    assertEquals(String.class, LogEntryKey.REQUEST_NAME.getClassification());
    assertEquals(String.class, LogEntryKey.METHOD.getClassification());
    assertEquals(String.class, LogEntryKey.URL.getClassification());
    assertEquals(Boolean.class, LogEntryKey.HAS_PARAMETER.getClassification());
    assertEquals(Integer.class, LogEntryKey.PARAMETER_COUNT.getClassification());
    assertEquals(Short.class, LogEntryKey.STATUS_CODE.getClassification());
    assertEquals(String.class, LogEntryKey.MIME.getClassification());
    assertEquals(String.class, LogEntryKey.EXTENSION.getClassification());
    assertEquals(Boolean.class, LogEntryKey.IS_DUPLICATED.getClassification());
    assertEquals(Boolean.class, LogEntryKey.IS_SIMILAR.getClassification());
    assertEquals(String.class, LogEntryKey.CHECKED_MESSAGE.getClassification());
    assertEquals(Boolean.class, LogEntryKey.TARGET_AUTO.getClassification());
    assertEquals(Boolean.class, LogEntryKey.TARGET_MANUAL.getClassification());
    assertEquals(String.class, LogEntryKey.DATE.getClassification());
    assertEquals(String.class, LogEntryKey.PAGE_TITLE.getClassification());
    assertEquals(String.class, LogEntryKey.REMARK.getClassification());
  }

  @Test
  void testGetDisplayName() {
    assertEquals("No", LogEntryKey.NUMBER.getDisplayName());
    assertEquals("リクエスト名", LogEntryKey.REQUEST_NAME.getDisplayName());
    assertEquals("メソッド", LogEntryKey.METHOD.getDisplayName());
    assertEquals("URL", LogEntryKey.URL.getDisplayName());
    assertEquals("パラメータ有無", LogEntryKey.HAS_PARAMETER.getDisplayName());
    assertEquals("パラメータ数", LogEntryKey.PARAMETER_COUNT.getDisplayName());
    assertEquals("ステータス", LogEntryKey.STATUS_CODE.getDisplayName());
    assertEquals("MIME", LogEntryKey.MIME.getDisplayName());
    assertEquals("拡張子", LogEntryKey.EXTENSION.getDisplayName());
    assertEquals("重複", LogEntryKey.IS_DUPLICATED.getDisplayName());
    assertEquals("類似", LogEntryKey.IS_SIMILAR.getDisplayName());
    assertEquals("確認箇所", LogEntryKey.CHECKED_MESSAGE.getDisplayName());
    assertEquals("自動対象", LogEntryKey.TARGET_AUTO.getDisplayName());
    assertEquals("手動対象", LogEntryKey.TARGET_MANUAL.getDisplayName());
    assertEquals("日時", LogEntryKey.DATE.getDisplayName());
    assertEquals("画面名", LogEntryKey.PAGE_TITLE.getDisplayName());
    assertEquals("備考", LogEntryKey.REMARK.getDisplayName());
  }

  @Test
  void testGetWidth() {
    assertEquals(50, LogEntryKey.NUMBER.getWidth());
    assertEquals(350, LogEntryKey.REQUEST_NAME.getWidth());
    assertEquals(60, LogEntryKey.METHOD.getWidth());
    assertEquals(350, LogEntryKey.URL.getWidth());
    assertEquals(50, LogEntryKey.HAS_PARAMETER.getWidth());
    assertEquals(50, LogEntryKey.PARAMETER_COUNT.getWidth());
    assertEquals(60, LogEntryKey.STATUS_CODE.getWidth());
    assertEquals(60, LogEntryKey.MIME.getWidth());
    assertEquals(60, LogEntryKey.EXTENSION.getWidth());
    assertEquals(50, LogEntryKey.IS_DUPLICATED.getWidth());
    assertEquals(50, LogEntryKey.IS_SIMILAR.getWidth());
    assertEquals(80, LogEntryKey.CHECKED_MESSAGE.getWidth());
    assertEquals(50, LogEntryKey.TARGET_AUTO.getWidth());
    assertEquals(50, LogEntryKey.TARGET_MANUAL.getWidth());
    assertEquals(130, LogEntryKey.DATE.getWidth());
    assertEquals(130, LogEntryKey.PAGE_TITLE.getWidth());
    assertEquals(300, LogEntryKey.REMARK.getWidth());
  }

  @Test
  void testHasTooltip() {
    assertFalse(LogEntryKey.NUMBER.hasTooltip());
    assertTrue(LogEntryKey.REQUEST_NAME.hasTooltip());
    assertFalse(LogEntryKey.METHOD.hasTooltip());
    assertTrue(LogEntryKey.URL.hasTooltip());
    assertFalse(LogEntryKey.HAS_PARAMETER.hasTooltip());
    assertFalse(LogEntryKey.PARAMETER_COUNT.hasTooltip());
    assertFalse(LogEntryKey.STATUS_CODE.hasTooltip());
    assertFalse(LogEntryKey.MIME.hasTooltip());
    assertFalse(LogEntryKey.EXTENSION.hasTooltip());
    assertFalse(LogEntryKey.IS_DUPLICATED.hasTooltip());
    assertFalse(LogEntryKey.IS_SIMILAR.hasTooltip());
    assertFalse(LogEntryKey.CHECKED_MESSAGE.hasTooltip());
    assertFalse(LogEntryKey.TARGET_AUTO.hasTooltip());
    assertFalse(LogEntryKey.TARGET_MANUAL.hasTooltip());
    assertTrue(LogEntryKey.DATE.hasTooltip());
    assertTrue(LogEntryKey.PAGE_TITLE.hasTooltip());
    assertTrue(LogEntryKey.REMARK.hasTooltip());
  }

  @Test
  void testIsEditable() {
    assertTrue(LogEntryKey.NUMBER.isEditable());
    assertTrue(LogEntryKey.REQUEST_NAME.isEditable());
    assertTrue(LogEntryKey.METHOD.isEditable());
    assertFalse(LogEntryKey.URL.isEditable());
    assertTrue(LogEntryKey.HAS_PARAMETER.isEditable());
    assertTrue(LogEntryKey.PARAMETER_COUNT.isEditable());
    assertFalse(LogEntryKey.STATUS_CODE.isEditable());
    assertFalse(LogEntryKey.MIME.isEditable());
    assertFalse(LogEntryKey.EXTENSION.isEditable());
    assertTrue(LogEntryKey.IS_DUPLICATED.isEditable());
    assertTrue(LogEntryKey.IS_SIMILAR.isEditable());
    assertFalse(LogEntryKey.CHECKED_MESSAGE.isEditable());
    assertTrue(LogEntryKey.TARGET_AUTO.isEditable());
    assertTrue(LogEntryKey.TARGET_MANUAL.isEditable());
    assertFalse(LogEntryKey.DATE.isEditable());
    assertTrue(LogEntryKey.PAGE_TITLE.isEditable());
    assertTrue(LogEntryKey.REMARK.isEditable());
  }

  @Test
  void testParseFromString() {
    assertEquals(100, LogEntryKey.NUMBER.parseFromString("100"));
    assertEquals("TEST", LogEntryKey.REQUEST_NAME.parseFromString("TEST"));
    assertEquals("GET", LogEntryKey.METHOD.parseFromString("GET"));
    assertEquals("https://example.com", LogEntryKey.URL.parseFromString("https://example.com"));
    assertEquals(true, LogEntryKey.HAS_PARAMETER.parseFromString("true"));
    assertEquals(25, LogEntryKey.PARAMETER_COUNT.parseFromString("25"));
    assertEquals((short) 200, LogEntryKey.STATUS_CODE.parseFromString("200"));
    assertEquals("png", LogEntryKey.MIME.parseFromString("png"));
    assertEquals("txt", LogEntryKey.EXTENSION.parseFromString("txt"));
    assertEquals(false, LogEntryKey.IS_DUPLICATED.parseFromString("false"));
    assertEquals(false, LogEntryKey.IS_SIMILAR.parseFromString("false"));
    assertEquals("No1", LogEntryKey.CHECKED_MESSAGE.parseFromString("No1"));
    assertEquals(true, LogEntryKey.TARGET_AUTO.parseFromString("true"));
    assertEquals(false, LogEntryKey.TARGET_MANUAL.parseFromString("false"));
    assertEquals("23:23:33 12 Oct 2022", LogEntryKey.DATE.parseFromString("23:23:33 12 Oct 2022"));
    assertEquals("画面名", LogEntryKey.PAGE_TITLE.parseFromString("画面名"));
    assertEquals("備考", LogEntryKey.REMARK.parseFromString("備考"));
  }
}
