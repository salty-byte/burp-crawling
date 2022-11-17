package models;

import static mocks.DummyDataUtils.createIHttpRequestResponse;
import static mocks.DummyDataUtils.createIParameter;
import static mocks.DummyDataUtils.createIRequestInfo;
import static mocks.DummyDataUtils.createIResponseInfo;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import burp.IParameter;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.List;
import org.junit.jupiter.api.Test;

class LogEntryTest {

  @Test
  void testConstructorOnlyNumber() {
    final var entry = new LogEntry(1);
    assertEquals(1, entry.getNumber());
    assertEquals("", entry.getPageTitle());
    assertEquals("", entry.getRequestName());
    assertEquals("https://", entry.getUrl());
    assertEquals("GET", entry.getMethod());
    assertEquals((short) 0, entry.getStatusCode());
    assertEquals("", entry.getMime());
    assertEquals("", entry.getExtension());
    assertFalse(entry.hasParameter());
    assertEquals(0, entry.getParameterCount());
    assertEquals("", entry.getRemark());
    assertFalse(entry.hasRequest());
    assertNull(entry.getRequestResponse());
    assertFalse(entry.isDuplicated());
    assertFalse(entry.isSimilar());
    assertEquals("", entry.getCheckedMessage());
    assertEquals(TargetType.NONE, entry.getTargetType());
    assertEquals(ColorType.DEFAULT, entry.getColorType());
    assertNotNull(entry.getDate());
  }

  @Test
  void testConstructorWithRequest() throws MalformedURLException {
    final var param = List.of(
        createIParameter(IParameter.PARAM_URL, "a", "1"),
        createIParameter(IParameter.PARAM_URL, "b", "3"),
        createIParameter(IParameter.PARAM_COOKIE, "c"),
        createIParameter(IParameter.PARAM_BODY, "d", "aa")
    );
    final var url = new URL("https://example.com/test.php?a=1&b=3");
    final var requestInfo = createIRequestInfo("POST", url, param);
    final var requestResponse = createIHttpRequestResponse();
    final var responseInfo = createIResponseInfo((short) 200, "mime");
    final var entry = new LogEntry(1, requestResponse, requestInfo, responseInfo);
    assertEquals(1, entry.getNumber());
    assertEquals("", entry.getPageTitle());
    assertEquals("", entry.getRequestName());
    assertEquals("https://example.com/test.php?a=1&b=3", entry.getUrl());
    assertEquals("POST", entry.getMethod());
    assertEquals((short) 200, entry.getStatusCode());
    assertEquals("mime", entry.getMime());
    assertEquals("php", entry.getExtension());
    assertTrue(entry.hasParameter());
    assertEquals(3, entry.getParameterCount());
    assertEquals("comment", entry.getRemark());
    assertTrue(entry.hasRequest());
    assertNotNull(entry.getRequestResponse());
    assertFalse(entry.isDuplicated());
    assertFalse(entry.isSimilar());
    assertEquals("", entry.getCheckedMessage());
    assertEquals(TargetType.NONE, entry.getTargetType());
    assertEquals(ColorType.DEFAULT, entry.getColorType());
    assertNotNull(entry.getDate());
  }

  @Test
  void testConstructorWithRequestIfNoParameter() throws MalformedURLException {
    final var param = List.of(
        createIParameter(IParameter.PARAM_COOKIE, "a")
    );
    final var url = new URL("https://example.com/test.php");
    final var requestInfo = createIRequestInfo("GET", url, param);
    final var requestResponse = createIHttpRequestResponse();
    final var responseInfo = createIResponseInfo((short) 200, "mime");
    final var entry = new LogEntry(1, requestResponse, requestInfo, responseInfo);
    assertEquals(0, entry.getParameterCount());
    assertFalse(entry.hasParameter());
  }
}
