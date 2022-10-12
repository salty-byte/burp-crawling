package models.json;

import static mocks.DummyDataUtils.createEmptyLogEntry;
import static mocks.DummyDataUtils.createLogEntry;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import models.ColorType;
import models.TargetType;
import org.junit.jupiter.api.Test;
import utils.JsonUtils;

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
    final var jsonStr = JsonUtils.toJson(logEntryForJson, LogEntryForJson.class);
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
    assertTrue(jsonStr.contains("\"statusCode\":200"), String.format("%s has statusCode", jsonStr));
    assertTrue(jsonStr.contains("\"mime\":\"HTML\""), String.format("%s has mime", jsonStr));
    assertTrue(
        jsonStr.contains("\"extension\":\"html\""),
        String.format("%s has extension", jsonStr)
    );
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
    assertTrue(jsonStr.contains("\"targetType\":0"), String.format("%s has targetType", jsonStr));
    assertTrue(jsonStr.contains("\"colorType\":0"), String.format("%s has colorType", jsonStr));
    assertTrue(jsonStr.contains("\"date\":"), String.format("%s has date", jsonStr));
    assertTrue(jsonStr.contains("\"remark\":\"test\""), String.format("%s has remark", jsonStr));

    final var reqResBlock = jsonStr.split("requestResponse")[1];
    assertTrue(
        reqResBlock.contains("\"request\":\"cmVxdWVzdA\""),
        String.format("%s has request", reqResBlock)
    );
    assertTrue(
        reqResBlock.contains("\"response\":\"cmVzcG9uc2U\""),
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
        "{\"number\":1,\"requestName\":\"top\",\"url\":\"https://example.com\",\"method\":\"GET\",\"statusCode\":200,\"mime\":\"text\",\"extension\":\"txt\",\"hasParameter\":true,\"duplicated\":true,\"duplicatedMessage\":\"\",\"targetType\":1,\"colorType\":3,\"date\":\"12:34:56 10 Oct 2022\",\"remark\":\"test\","
            + "\"requestResponse\":{\"request\":\"cmVxdWVzdA\",\"response\":\"cmVzcG9uc2U\","
            + "\"origin\":{\"host\":\"example.com\",\"port\":443,\"protocol\":\"https\"}"
            + "}}";
    final var logEntryForJson = JsonUtils.fromJson(jsonStr, LogEntryForJson.class);
    assertEquals(1, logEntryForJson.getNumber());
    assertEquals("top", logEntryForJson.getRequestName());
    assertEquals("https://example.com", logEntryForJson.getUrl());
    assertEquals("GET", logEntryForJson.getMethod());
    assertEquals((short) 200, logEntryForJson.getStatusCode());
    assertEquals("text", logEntryForJson.getMime());
    assertEquals("txt", logEntryForJson.getExtension());
    assertTrue(logEntryForJson.hasParameter());
    assertTrue(logEntryForJson.isDuplicated());
    assertEquals("", logEntryForJson.getDuplicatedMessage());
    assertEquals(TargetType.AUTO, logEntryForJson.getTargetType());
    assertEquals(ColorType.YELLOW, logEntryForJson.getColorType());
    assertEquals("12:34:56 10 Oct 2022", logEntryForJson.getDate());
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
