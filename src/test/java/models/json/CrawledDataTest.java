package models.json;

import static mocks.DummyDataUtils.createLogEntry;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;
import utils.JsonUtils;

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
    final var jsonStr = JsonUtils.toJson(crawledData, CrawledData.class);
    assertTrue(jsonStr.contains("\"version\":\"1.0\""), String.format("%s has version", jsonStr));
    assertTrue(jsonStr.contains("\"entries\":["), String.format("%s has entries", jsonStr));
  }

  @Test
  void testFromJson() {
    final var jsonStr = "{\"version\":\"1.0\",\"entries\":["
        + "{\"number\":1,\"requestName\":\"top\",\"url\":\"https://example.com\",\"method\":\"GET\",\"statusCode\":200,\"mime\":\"png\",\"hasParameter\":false,\"duplicated\":false,\"duplicatedMessage\":\"\",\"remark\":\"test\",\"colorType\":1,\"requestResponse\":{\"request\":\"cmVxdWVzdA\",\"response\":\"cmVzcG9uc2U\",\"origin\":{\"host\":\"example.com\",\"port\":443,\"protocol\":\"https\"}}}"
        + "]}";
    final var crawledData = JsonUtils.fromJson(jsonStr, CrawledData.class);
    assertEquals("1.0", crawledData.getVersion());

    final var logEntryForJson = crawledData.getEntries().get(0);
    assertEquals(1, logEntryForJson.getNumber());
    assertEquals("top", logEntryForJson.getRequestName());
    assertEquals("https://example.com", logEntryForJson.getUrl());
    assertEquals("GET", logEntryForJson.getMethod());
    assertEquals((short) 200, logEntryForJson.getStatusCode());
    assertEquals("png", logEntryForJson.getMime());
    assertFalse(logEntryForJson.hasParameter());
    assertFalse(logEntryForJson.isDuplicated());
    assertEquals("", logEntryForJson.getDuplicatedMessage());
    assertEquals((byte) 0x0, logEntryForJson.getTargetType());
    assertEquals((byte) 0x1, logEntryForJson.getColorType());
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
