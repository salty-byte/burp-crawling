package models.json;

import static mocks.DummyDataUtils.createLogEntry;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.google.gson.Gson;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;

class CrawledDataTest {

  @Test
  void testConstructorWhenArgumentIsCorrect() {
    final var list = List.of(createLogEntry());
    assertDoesNotThrow(() -> new CrawledData(list));
    assertDoesNotThrow(() -> new CrawledData(new ArrayList<>()));
  }

  @Test
  void testConstructorWhenArgumentIsNull() {
    assertThrows(NullPointerException.class, () -> new CrawledData(null));
  }

  @Test
  void testToJson() {
    final var list = List.of(createLogEntry());
    final var crawledData = new CrawledData(list);
    final var jsonStr = new Gson().toJson(crawledData, CrawledData.class);
    assertTrue(jsonStr.contains("\"version\":\"1.0\""), String.format("%s has version", jsonStr));
    assertTrue(jsonStr.contains("\"entries\":["), String.format("%s has entries", jsonStr));
  }

  @Test
  void testFromJson() {
    final var jsonStr = "{\"version\":\"1.0\",\"entries\":["
        + "{\"number\":1,\"requestName\":\"top\",\"url\":\"https://example.com\",\"method\":\"GET\",\"hasParameter\":false,\"duplicated\":false,\"duplicatedMessage\":\"\",\"remark\":\"test\",\"requestResponse\":{\"request\":[114,101,113,117,101,115,116],\"response\":[114,101,115,112,111,110,115,101],\"origin\":{\"host\":\"example.com\",\"port\":443,\"protocol\":\"https\"}}}"
        + "]}";
    final var crawledData = new Gson().fromJson(jsonStr, CrawledData.class);
    assertEquals("1.0", crawledData.getVersion());

    final var logEntryForJson = crawledData.getEntries().get(0);
    assertEquals(1, logEntryForJson.getNumber());
    assertEquals("top", logEntryForJson.getRequestName());
    assertEquals("https://example.com", logEntryForJson.getUrl());
    assertEquals("GET", logEntryForJson.getMethod());
    assertFalse(logEntryForJson.hasParameter());
    assertFalse(logEntryForJson.isDuplicated());
    assertEquals("", logEntryForJson.getDuplicatedMessage());
    assertEquals("test", logEntryForJson.getRemark());

    final var requestResponse = logEntryForJson.getRequestResponse();
    assertArrayEquals("request".getBytes(StandardCharsets.UTF_8), requestResponse.getRequest());
    assertArrayEquals("response".getBytes(StandardCharsets.UTF_8), requestResponse.getResponse());

    final var origin = requestResponse.getOrigin();
    assertEquals("example.com", origin.getHost());
    assertEquals(443, origin.getPort());
    assertEquals("https", origin.getProtocol());
  }
}
