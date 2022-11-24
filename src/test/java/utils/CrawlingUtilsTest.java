package utils;

import static mocks.DummyDataUtils.createIParameter;
import static mocks.DummyDataUtils.createIRequestInfo;
import static mocks.DummyDataUtils.createLogEntry;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.times;

import burp.IExtensionHelpers;
import burp.IParameter;
import java.awt.Toolkit;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.DataFlavor;
import java.awt.datatransfer.StringSelection;
import java.awt.datatransfer.UnsupportedFlavorException;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.util.List;
import java.util.TimeZone;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;

class CrawlingUtilsTest {

  private static IExtensionHelpers helpers;

  @BeforeAll
  static void init() throws MalformedURLException {
    helpers = Mockito.mock(IExtensionHelpers.class);
    final var param1 = List.of(
        createIParameter(IParameter.PARAM_URL, "a"),
        createIParameter(IParameter.PARAM_URL, "b")
    );
    final var param2 = List.of(
        createIParameter(IParameter.PARAM_URL, "b"),
        createIParameter(IParameter.PARAM_URL, "a"),
        createIParameter(IParameter.PARAM_COOKIE, "a")
    );
    final var param3 = List.of(
        createIParameter(IParameter.PARAM_URL, "a"),
        createIParameter(IParameter.PARAM_URL, "c")
    );
    final var param4 = List.of(
        createIParameter(IParameter.PARAM_BODY, "a"),
        createIParameter(IParameter.PARAM_BODY, "b"),
        createIParameter(IParameter.PARAM_COOKIE, "a")
    );
    final var param5 = List.of(
        createIParameter(IParameter.PARAM_URL, "a"),
        createIParameter(IParameter.PARAM_COOKIE, "b")
    );
    final var info1 = createIRequestInfo("GET", new URL("https://example.com/?a=1&b=3"), param1);
    final var info2 = createIRequestInfo("GET", new URL("https://example.com/?b=1&a=1"), param2);
    final var info3 = createIRequestInfo("GET", new URL("https://example.com/"), param3);
    final var info4 = createIRequestInfo("GET", new URL("https://example.com/test/test"), param1);
    final var info5 = createIRequestInfo("POST", new URL("https://example.com/"), param1);
    final var info6 = createIRequestInfo("PATCH", new URL("https://example.com/test"), param4);
    final var info7 = createIRequestInfo("GET", new URL("https://example.com/"), param5);
    final var info8 = createIRequestInfo("POST", new URL("https://example.com/1/edit/1"), param4);
    final var info9 = createIRequestInfo("POST", new URL("https://example.com/101/edit/1"), param4);
    final var info10 = createIRequestInfo("GET", new URL("https://example.com/test/te"), List.of());
    final var request1 = "1".getBytes(StandardCharsets.UTF_8);
    final var request2 = "2".getBytes(StandardCharsets.UTF_8);
    final var request3 = "3".getBytes(StandardCharsets.UTF_8);
    final var request4 = "4".getBytes(StandardCharsets.UTF_8);
    final var request5 = "5".getBytes(StandardCharsets.UTF_8);
    final var request6 = "6".getBytes(StandardCharsets.UTF_8);
    final var request7 = "7".getBytes(StandardCharsets.UTF_8);
    final var request8 = "8".getBytes(StandardCharsets.UTF_8);
    final var request9 = "9".getBytes(StandardCharsets.UTF_8);
    final var request10 = "10".getBytes(StandardCharsets.UTF_8);
    Mockito.when(helpers.analyzeRequest(any(), eq(request1))).thenReturn(info1);
    Mockito.when(helpers.analyzeRequest(any(), eq(request2))).thenReturn(info2);
    Mockito.when(helpers.analyzeRequest(any(), eq(request3))).thenReturn(info3);
    Mockito.when(helpers.analyzeRequest(any(), eq(request4))).thenReturn(info4);
    Mockito.when(helpers.analyzeRequest(any(), eq(request5))).thenReturn(info5);
    Mockito.when(helpers.analyzeRequest(any(), eq(request6))).thenReturn(info6);
    Mockito.when(helpers.analyzeRequest(any(), eq(request7))).thenReturn(info7);
    Mockito.when(helpers.analyzeRequest(any(), eq(request8))).thenReturn(info8);
    Mockito.when(helpers.analyzeRequest(any(), eq(request9))).thenReturn(info9);
    Mockito.when(helpers.analyzeRequest(any(), eq(request10))).thenReturn(info10);
  }

  @Test
  void testApplySimilarOrDuplicatedRequestRequest() {
    final var logEntries = List.of(
        createLogEntry(1, "1".getBytes(StandardCharsets.UTF_8)),
        createLogEntry(2, "2".getBytes(StandardCharsets.UTF_8)),
        createLogEntry(3, "3".getBytes(StandardCharsets.UTF_8)),
        createLogEntry(4, "4".getBytes(StandardCharsets.UTF_8)),
        createLogEntry(5, "5".getBytes(StandardCharsets.UTF_8)),
        createLogEntry(6, "6".getBytes(StandardCharsets.UTF_8)),
        createLogEntry(7, "1".getBytes(StandardCharsets.UTF_8)),
        createLogEntry(8, "2".getBytes(StandardCharsets.UTF_8)),
        createLogEntry(9, "6".getBytes(StandardCharsets.UTF_8)),
        createLogEntry(10, "7".getBytes(StandardCharsets.UTF_8)),
        createLogEntry(11, "4".getBytes(StandardCharsets.UTF_8)),
        createLogEntry(12, "8".getBytes(StandardCharsets.UTF_8)),
        createLogEntry(13, "9".getBytes(StandardCharsets.UTF_8)),
        createLogEntry(14, "10".getBytes(StandardCharsets.UTF_8))
    );
    CrawlingUtils.applySimilarOrDuplicatedRequest(logEntries, helpers);
    final var entry1 = logEntries.get(0);
    assertFalse(entry1.isDuplicated());
    assertFalse(entry1.isSimilar());
    final var entry2 = logEntries.get(1);
    assertTrue(entry2.isDuplicated());
    assertEquals("No1", entry2.getCheckedMessage());
    final var entry3 = logEntries.get(2);
    assertFalse(entry3.isDuplicated());
    assertFalse(entry3.isSimilar());
    final var entry7 = logEntries.get(6);
    assertTrue(entry7.isDuplicated());
    assertEquals("No1", entry7.getCheckedMessage());
    final var entry8 = logEntries.get(7);
    assertTrue(entry8.isDuplicated());
    assertEquals("No1", entry8.getCheckedMessage());
    final var entry9 = logEntries.get(8);
    assertTrue(entry9.isDuplicated());
    assertEquals("No6", entry9.getCheckedMessage());
    final var entry10 = logEntries.get(9);
    assertTrue(entry10.isSimilar());
    assertEquals("No1", entry10.getCheckedMessage());
    final var entry11 = logEntries.get(10);
    assertTrue(entry11.isDuplicated());
    assertEquals("No4", entry11.getCheckedMessage());
    final var entry12 = logEntries.get(11);
    assertFalse(entry12.isDuplicated());
    assertFalse(entry12.isSimilar());
    final var entry13 = logEntries.get(12);
    assertTrue(entry13.isDuplicated());
    assertEquals("No12", entry13.getCheckedMessage());
    final var entry14 = logEntries.get(13);
    assertFalse(entry14.isDuplicated());
    assertFalse(entry14.isSimilar());
  }

  @Test
  void testApplySimilarOrDuplicatedRequestRequestWithArrays() throws MalformedURLException {
    final var param1 = List.of(
        createIParameter(IParameter.PARAM_BODY, "a[]"),
        createIParameter(IParameter.PARAM_BODY, "b"),
        createIParameter(IParameter.PARAM_COOKIE, "a")
    );
    final var param2 = List.of(
        createIParameter(IParameter.PARAM_BODY, "a[]"),
        createIParameter(IParameter.PARAM_BODY, "a[]"),
        createIParameter(IParameter.PARAM_BODY, "b"),
        createIParameter(IParameter.PARAM_COOKIE, "a")
    );
    final var param3 = List.of(
        createIParameter(IParameter.PARAM_BODY, "a[]"),
        createIParameter(IParameter.PARAM_BODY, "a[]"),
        createIParameter(IParameter.PARAM_BODY, "b"),
        createIParameter(IParameter.PARAM_COOKIE, "b")
    );
    final var param4 = List.of(
        createIParameter(IParameter.PARAM_URL, "a"),
        createIParameter(IParameter.PARAM_URL, "b"),
        createIParameter(IParameter.PARAM_URL, "b"),
        createIParameter(IParameter.PARAM_URL, "c"),
        createIParameter(IParameter.PARAM_COOKIE, "b")
    );
    final var info1 = createIRequestInfo("POST", new URL("https://example.com/arrays/"), param1);
    final var info2 = createIRequestInfo("POST", new URL("https://example.com/arrays/"), param2);
    final var info3 = createIRequestInfo("POST", new URL("https://example.com/arrays/"), param3);
    final var info4 = createIRequestInfo("POST",
        new URL("https://example.com/arrays/?a=3&b=5&b=4&c=1"), param4);
    final var request1 = "array1".getBytes(StandardCharsets.UTF_8);
    final var request2 = "array2".getBytes(StandardCharsets.UTF_8);
    final var request3 = "array3".getBytes(StandardCharsets.UTF_8);
    final var request4 = "array4".getBytes(StandardCharsets.UTF_8);
    Mockito.when(helpers.analyzeRequest(any(), eq(request1))).thenReturn(info1);
    Mockito.when(helpers.analyzeRequest(any(), eq(request2))).thenReturn(info2);
    Mockito.when(helpers.analyzeRequest(any(), eq(request3))).thenReturn(info3);
    Mockito.when(helpers.analyzeRequest(any(), eq(request4))).thenReturn(info4);

    final var logEntries = List.of(
        createLogEntry(1, "array1".getBytes(StandardCharsets.UTF_8)),
        createLogEntry(2, "array2".getBytes(StandardCharsets.UTF_8)),
        createLogEntry(3, "array4".getBytes(StandardCharsets.UTF_8)),
        createLogEntry(4, "array3".getBytes(StandardCharsets.UTF_8)),
        createLogEntry(5, "array4".getBytes(StandardCharsets.UTF_8))
    );
    CrawlingUtils.applySimilarOrDuplicatedRequest(logEntries, helpers);
    final var entry1 = logEntries.get(0);
    assertFalse(entry1.isDuplicated());
    assertFalse(entry1.isSimilar());
    final var entry2 = logEntries.get(1);
    assertTrue(entry2.isDuplicated());
    assertEquals("No1", entry2.getCheckedMessage());
    final var entry3 = logEntries.get(2);
    assertFalse(entry3.isDuplicated());
    assertFalse(entry3.isSimilar());
    final var entry4 = logEntries.get(3);
    assertTrue(entry4.isDuplicated());
    assertEquals("No1", entry4.getCheckedMessage());
    final var entry5 = logEntries.get(4);
    assertTrue(entry5.isDuplicated());
    assertEquals("No3", entry5.getCheckedMessage());
  }

  @Test
  void testApplyRequestNameHash() {
    final var logEntries = List.of(
        createLogEntry(1, "TOP"),
        createLogEntry(2, "TOP>ログイン"),
        createLogEntry(3, "TOP>ログイン>ログイン"),
        createLogEntry(4, "TOP>ログイン>ログイン"),
        createLogEntry(5, "ログイン>マイページ"),
        createLogEntry(6, "ログイン>マイページ>パスワード変更#2"),
        createLogEntry(7, "ログイン>マイページ>パスワード変更>変更"),
        createLogEntry(8, "TOP#a"),
        createLogEntry(9, "TOP>ログイン"),
        createLogEntry(10, "TOP>ログイン>SNSログイン"),
        createLogEntry(11, "TOP>ログイン>SNSログイン#2"),
        createLogEntry(12, "TOP>ログイン>SNSログイン#4"),
        createLogEntry(13, ""),
        createLogEntry(14, "#12")
    );
    CrawlingUtils.applyRequestNameHash(logEntries);
    assertEquals("TOP", logEntries.get(0).getRequestName());
    assertEquals("TOP>ログイン", logEntries.get(1).getRequestName());
    assertEquals("TOP>ログイン>ログイン", logEntries.get(2).getRequestName());
    assertEquals("TOP>ログイン>ログイン#2", logEntries.get(3).getRequestName());
    assertEquals("ログイン>マイページ", logEntries.get(4).getRequestName());
    assertEquals("ログイン>マイページ>パスワード変更", logEntries.get(5).getRequestName());
    assertEquals("ログイン>マイページ>パスワード変更>変更", logEntries.get(6).getRequestName());
    assertEquals("TOP", logEntries.get(7).getRequestName());
    assertEquals("TOP>ログイン", logEntries.get(8).getRequestName());
    assertEquals("TOP>ログイン>SNSログイン", logEntries.get(9).getRequestName());
    assertEquals("TOP>ログイン>SNSログイン#2", logEntries.get(10).getRequestName());
    assertEquals("TOP>ログイン>SNSログイン#3", logEntries.get(11).getRequestName());
    assertEquals("", logEntries.get(12).getRequestName());
    assertEquals("", logEntries.get(13).getRequestName());
  }

  @ParameterizedTest
  @CsvSource({
      "https://example.com/test, ''",
      "https://example.com/test.a/, ''",
      "https://example.com/test/file., ''",
      "https://example.com:8080/test.php?a=1&b=2, php",
      "http://user:password@172.168.1.56:8088/a/b.dir/c.text.html#hash, html"
  })
  void testFindExtension(final URL url, final String expected) {
    assertEquals(expected, CrawlingUtils.findExtension(url));
  }

  @Test
  void testCreateDateString() {
    TimeZone.setDefault(TimeZone.getTimeZone("Asia/Tokyo"));
    final var clock = Clock.fixed(Instant.parse("2022-12-12T03:34:56Z"), ZoneId.of("Asia/Tokyo"));
    final var instant = Instant.now(clock);
    try (final var mocked = Mockito.mockStatic(Instant.class)) {
      mocked.when(Instant::now).thenReturn(instant);
      assertEquals("12:34:56 12 Dec 2022", CrawlingUtils.createDateString());
    }
  }

  @ParameterizedTest
  @CsvSource({
      "https://example.com/test, https://example.com/test",
      "https://example.com:8080/test?a=1&b=2, https://example.com:8080/test",
      "https://example.com:80/test, https://example.com:80/test",
      "http://example.com:443/test?/a??=#hash, http://example.com:443/test",
      "http://user:password@172.168.1.56:8088/a/b/c#hash, http://172.168.1.56:8088/a/b/c"
  })
  void testCreateUrlString(final URL url, final String expected) {
    assertEquals(expected, CrawlingUtils.createUrlString(url));
  }


  @ParameterizedTest
  @CsvSource({
      "https://example.com/test, https://example.com/test",
      "https://example.com:8080/test?a=1&b=2, https://example.com:8080/test?a=1&b=2",
      "https://example.com:80/test, https://example.com:80/test",
      "http://example.com:443/test?/a??=#hash, http://example.com:443/test?/a??=",
      "http://user:password@172.168.1.56:8088/a/b/c#hash, http://172.168.1.56:8088/a/b/c"
  })
  void testCreateUrlStringWithQuery(final URL url, final String expected) {
    assertEquals(expected, CrawlingUtils.createUrlStringWithQuery(url));
  }

  @ParameterizedTest
  @CsvSource({
      "test",
      "https://example.com:8080/\ttrue\ttrue\nhttps://example.com:8080/test?a=1&b=2\tfalse\ttrue",
  })
  void testExportToClipBoard(final String message) throws IOException, UnsupportedFlavorException {
    // use mocks to avoid java.awt.HeadlessException in Toolkit#getSystemClipboard
    final var captor = ArgumentCaptor.forClass(StringSelection.class);
    final var toolkit = Mockito.mock(Toolkit.class);
    final var clipboard = Mockito.mock(Clipboard.class);
    Mockito.doNothing().when(clipboard).setContents(captor.capture(), captor.capture());
    Mockito.doReturn(clipboard).when(toolkit).getSystemClipboard();
    try (final var mocked = Mockito.mockStatic(Toolkit.class)) {
      mocked.when(Toolkit::getDefaultToolkit).thenReturn(toolkit);

      // do the target method
      CrawlingUtils.exportToClipBoard(message);
    }

    Mockito.verify(clipboard, times(1)).setContents(any(), any());
    for (final var selection : captor.getAllValues()) {
      final var result = selection.getTransferData(DataFlavor.stringFlavor).toString();
      assertEquals(message, result);
    }
  }
}
