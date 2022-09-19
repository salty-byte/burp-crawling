package models.json;

import static models.json.DummyDataUtils.createEmptyIHttpRequestResponse;
import static models.json.DummyDataUtils.createIHttpRequestResponse;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.google.gson.Gson;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

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
    final var jsonStr = new Gson().toJson(requestResponse, RequestResponse.class);
    assertTrue(
        jsonStr.contains("\"request\":[114,101,113,117,101,115,116]"),
        String.format("%s has request", jsonStr)
    );
    assertTrue(
        jsonStr.contains("\"response\":[114,101,115,112,111,110,115,101]"),
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
    final var jsonStr = "{\"request\":[114,101,113,117,101,115,116],\"response\":[114,101,115,112,111,110,115,101],\"origin\":{\"host\":\"example.com\",\"port\":443,\"protocol\":\"https\"}}";
    final var requestResponse = new Gson().fromJson(jsonStr, RequestResponse.class);
    assertArrayEquals("request".getBytes(StandardCharsets.UTF_8), requestResponse.getRequest());
    assertArrayEquals("response".getBytes(StandardCharsets.UTF_8), requestResponse.getResponse());

    final var origin = requestResponse.getOrigin();
    assertEquals("example.com", origin.getHost());
    assertEquals(443, origin.getPort());
    assertEquals("https", origin.getProtocol());
  }
}
