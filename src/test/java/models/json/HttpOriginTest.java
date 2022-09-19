package models.json;

import static models.json.DummyDataUtils.createEmptyIHttpService;
import static models.json.DummyDataUtils.createIHttpService;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.google.gson.Gson;
import org.junit.jupiter.api.Test;

class HttpOriginTest {

  @Test
  void testConstructorWhenArgumentIsCorrect() {
    assertDoesNotThrow(() -> new HttpOrigin(createIHttpService()));
    assertDoesNotThrow(() -> new HttpOrigin(createEmptyIHttpService()));
  }

  @Test
  void testConstructorWhenArgumentIsNull() {
    assertThrows(NullPointerException.class, () -> new HttpOrigin(null));
  }

  @Test
  void testToJson() {
    final var origin = new HttpOrigin(createIHttpService());
    final var jsonStr = new Gson().toJson(origin, HttpOrigin.class);
    assertTrue(jsonStr.contains("\"host\":\"example.com\""), String.format("%s has host", jsonStr));
    assertTrue(jsonStr.contains("\"port\":443"), String.format("%s has port", jsonStr));
    assertTrue(jsonStr.contains("\"protocol\":\"https\""),
        String.format("%s has protocol", jsonStr));
  }

  @Test
  void testFromJson() {
    final var jsonStr = "{\"host\":\"example.com\",\"port\":443,\"protocol\":\"https\"}";
    final var origin = new Gson().fromJson(jsonStr, HttpOrigin.class);
    assertEquals("example.com", origin.getHost());
    assertEquals(443, origin.getPort());
    assertEquals("https", origin.getProtocol());
  }
}
