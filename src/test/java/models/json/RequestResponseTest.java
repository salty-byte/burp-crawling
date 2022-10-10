package models.json;

import static mocks.DummyDataUtils.createEmptyIHttpRequestResponse;
import static mocks.DummyDataUtils.createIHttpRequestResponse;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;
import utils.JsonUtils;

class RequestResponseTest {

  @Test
  void testConstructorWhenArgumentIsCorrect() {
    assertDoesNotThrow(() -> new RequestResponse(createIHttpRequestResponse()));
    assertDoesNotThrow(() -> new RequestResponse(createEmptyIHttpRequestResponse()));
  }

  @Test
  void testConstructorWhenArgumentIsNull() {
    assertThrows(NullPointerException.class, () -> new RequestResponse(null));
  }

  @Test
  void testToJson() {
    final var requestResponse = new RequestResponse(createIHttpRequestResponse());
    final var jsonStr = JsonUtils.toJson(requestResponse, RequestResponse.class);
    assertTrue(
        jsonStr.contains("\"request\":\"cmVxdWVzdA\""),
        String.format("%s has request", jsonStr)
    );
    assertTrue(
        jsonStr.contains("\"response\":\"cmVzcG9uc2U\""),
        String.format("%s has response", jsonStr)
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
    final var jsonStr = "{\"request\":\"cmVxdWVzdA\",\"response\":\"cmVzcG9uc2U\",\"origin\":{\"host\":\"example.com\",\"port\":443,\"protocol\":\"https\"}}";
    final var requestResponse = JsonUtils.fromJson(jsonStr, RequestResponse.class);
    assertArrayEquals("request".getBytes(StandardCharsets.UTF_8), requestResponse.getRequest());
    assertArrayEquals("response".getBytes(StandardCharsets.UTF_8), requestResponse.getResponse());

    final var origin = requestResponse.getOrigin();
    assertEquals("example.com", origin.getHost());
    assertEquals(443, origin.getPort());
    assertEquals("https", origin.getProtocol());
  }
}
