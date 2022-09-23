package models.json;

import static mocks.DummyDataUtils.createEmptyLogEntry;
import static mocks.DummyDataUtils.createLogEntry;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.google.gson.Gson;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

class LogEntryForJsonTest {

  @Test
  void testConstructorWhenArgumentIsCorrect() {
    assertDoesNotThrow(() -> new LogEntryForJson(createLogEntry()));
    assertDoesNotThrow(() -> new LogEntryForJson(createEmptyLogEntry()));
  }

  @Test
  void testConstructorWhenArgumentIsNull() {
    assertThrows(NullPointerException.class, () -> new LogEntryForJson(null));
  }

  @Test
  void testToJson() {
    final var logEntryForJson = new LogEntryForJson(createLogEntry());
    final var jsonStr = new Gson().toJson(logEntryForJson, LogEntryForJson.class);
    assertTrue(jsonStr.contains("\"number\":1"), String.format("%s has number", jsonStr));
    assertTrue(
        jsonStr.contains("\"requestName\":\"top\""),
        String.format("%s has requestName", jsonStr)
    );
    assertTrue(
        jsonStr.contains("\"url\":\"https://example.com\""),
        String.format("%s has url", jsonStr)
    );
    assertTrue(jsonStr.contains("\"method\":\"GET\""), String.format("%s has method", jsonStr));
    assertTrue(
        jsonStr.contains("\"hasParameter\":false"),
        String.format("%s has hasParameter", jsonStr)
    );
    assertTrue(
        jsonStr.contains("\"duplicated\":false"),
        String.format("%s has duplicated", jsonStr)
    );
    assertTrue(
        jsonStr.contains("\"duplicatedMessage\":\"\""),
        String.format("%s has duplicatedMessage", jsonStr)
    );
    assertTrue(jsonStr.contains("\"remark\":\"test\""), String.format("%s has remark", jsonStr));

    final var reqResBlock = jsonStr.split("requestResponse")[1];
    assertTrue(
        reqResBlock.contains("\"request\":[114,101,113,117,101,115,116]"),
        String.format("%s has request", reqResBlock)
    );
    assertTrue(
        reqResBlock.contains("\"response\":[114,101,115,112,111,110,115,101]"),
        String.format("%s has response", reqResBlock)
    );

    final var originBlock = jsonStr.split("origin")[1];
    assertTrue(
        originBlock.contains("\"host\":\"example.com\""),
        String.format("%s has host", jsonStr)
    );
    assertTrue(originBlock.contains("\"port\":443"), String.format("%s has port", jsonStr));
    assertTrue(
        originBlock.contains("\"protocol\":\"https\""),
        String.format("%s has protocol", jsonStr)
    );
  }

  @Test
  void testFromJson() {
    final var jsonStr =
        "{\"number\":1,\"requestName\":\"top\",\"url\":\"https://example.com\",\"method\":\"GET\",\"hasParameter\":true,\"duplicated\":true,\"duplicatedMessage\":\"\",\"remark\":\"test\","
            + "\"requestResponse\":{\"request\":[114,101,113,117,101,115,116],\"response\":[114,101,115,112,111,110,115,101],"
            + "\"origin\":{\"host\":\"example.com\",\"port\":443,\"protocol\":\"https\"}"
            + "}}";
    final var logEntryForJson = new Gson().fromJson(jsonStr, LogEntryForJson.class);
    assertEquals(1, logEntryForJson.getNumber());
    assertEquals("top", logEntryForJson.getRequestName());
    assertEquals("https://example.com", logEntryForJson.getUrl());
    assertEquals("GET", logEntryForJson.getMethod());
    assertTrue(logEntryForJson.hasParameter());
    assertTrue(logEntryForJson.isDuplicated());
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