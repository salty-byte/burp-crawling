package utils;

import static mocks.DummyDataUtils.createIParameter;
import static mocks.DummyDataUtils.createIRequestInfo;
import static mocks.DummyDataUtils.createLogEntry;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;

import burp.IExtensionHelpers;
import burp.IParameter;
import java.awt.Toolkit;
import java.awt.datatransfer.DataFlavor;
import java.awt.datatransfer.UnsupportedFlavorException;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.List;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
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
        createIParameter(IParameter.PARAM_URL, "a")
    );
    final var param3 = List.of(
        createIParameter(IParameter.PARAM_URL, "a"),
        createIParameter(IParameter.PARAM_URL, "c")
    );
    final var param4 = List.of(
        createIParameter(IParameter.PARAM_BODY, "a"),
        createIParameter(IParameter.PARAM_BODY, "b")
    );
    final var param5 = List.of(
        createIParameter(IParameter.PARAM_URL, "a")
    );
    final var info1 = createIRequestInfo("GET", new URL("https://example.com/?a=1&b=3"), param1);
    final var info2 = createIRequestInfo("GET", new URL("https://example.com/?b=1&a=1"), param2);
    final var info3 = createIRequestInfo("GET", new URL("https://example.com/"), param3);
    final var info4 = createIRequestInfo("GET", new URL("https://example.com/test/"), param1);
    final var info5 = createIRequestInfo("POST", new URL("https://example.com/"), param1);
    final var info6 = createIRequestInfo("PATCH", new URL("https://example.com/test"), param4);
    final var info7 = createIRequestInfo("GET", new URL("https://example.com/"), param5);
    final var request1 = "1".getBytes(StandardCharsets.UTF_8);
    final var request2 = "2".getBytes(StandardCharsets.UTF_8);
    final var request3 = "3".getBytes(StandardCharsets.UTF_8);
    final var request4 = "4".getBytes(StandardCharsets.UTF_8);
    final var request5 = "5".getBytes(StandardCharsets.UTF_8);
    final var request6 = "6".getBytes(StandardCharsets.UTF_8);
    final var request7 = "7".getBytes(StandardCharsets.UTF_8);
    Mockito.when(helpers.analyzeRequest(any(), eq(request1))).thenReturn(info1);
    Mockito.when(helpers.analyzeRequest(any(), eq(request2))).thenReturn(info2);
    Mockito.when(helpers.analyzeRequest(any(), eq(request3))).thenReturn(info3);
    Mockito.when(helpers.analyzeRequest(any(), eq(request4))).thenReturn(info4);
    Mockito.when(helpers.analyzeRequest(any(), eq(request5))).thenReturn(info5);
    Mockito.when(helpers.analyzeRequest(any(), eq(request6))).thenReturn(info6);
    Mockito.when(helpers.analyzeRequest(any(), eq(request7))).thenReturn(info7);
  }

  @Test
  void testApplyDuplicatedRequest() {
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
        createLogEntry(10, "8".getBytes(StandardCharsets.UTF_8))
    );
    CrawlingUtils.applyDuplicatedRequest(logEntries, helpers);
    assertFalse(logEntries.get(0).isDuplicated());
    assertTrue(logEntries.get(1).isDuplicated());
    assertEquals("No1", logEntries.get(1).getDuplicatedMessage());
    assertFalse(logEntries.get(2).isDuplicated());
    assertFalse(logEntries.get(3).isDuplicated());
    assertFalse(logEntries.get(4).isDuplicated());
    assertFalse(logEntries.get(5).isDuplicated());
    assertTrue(logEntries.get(6).isDuplicated());
    assertEquals("No1", logEntries.get(6).getDuplicatedMessage());
    assertTrue(logEntries.get(7).isDuplicated());
    assertEquals("No1", logEntries.get(7).getDuplicatedMessage());
    assertTrue(logEntries.get(8).isDuplicated());
    assertEquals("No6", logEntries.get(8).getDuplicatedMessage());
    assertFalse(logEntries.get(9).isDuplicated());
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

  @ParameterizedTest
  @CsvSource({
      "https://example.com/test, https://example.com:443/test",
      "https://example.com:8080/test?a=1&b=2, https://example.com:8080/test",
      "http://user:password@172.168.1.56:8088/a/b/c#hash, http://172.168.1.56:8088/a/b/c"
  })
  void testCreateUrlString(final URL url, final String expected) {
    assertEquals(expected, CrawlingUtils.createUrlString(url));
  }

  @ParameterizedTest
  @CsvSource({
      "test",
      "https://example.com:8080/\ttrue\ttrue\nhttps://example.com:8080/test?a=1&b=2\tfalse\ttrue",
  })
  void testClipBoard(final String message) throws IOException, UnsupportedFlavorException {
    CrawlingUtils.toClipBoard(message);
    final var toolkit = Toolkit.getDefaultToolkit();
    final var clipboard = toolkit.getSystemClipboard();
    final var result = clipboard.getData(DataFlavor.stringFlavor);
    assertEquals(message, result);
  }
}
