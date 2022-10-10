package utils;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.google.gson.JsonSyntaxException;
import org.junit.jupiter.api.Test;

class JsonUtilsTest {

  @Test
  void testCreateGsonBuilder() {
    assertDoesNotThrow(JsonUtils::createGsonBuilder);
  }

  @Test
  void testToJson() {
    final var jsonStr = JsonUtils.toJson(new Sample(), Sample.class);
    assertTrue(
        jsonStr.contains("\"strValue\":\"sample\""),
        String.format("%s has strValue", jsonStr)
    );
    assertTrue(jsonStr.contains("\"intValue\":10000"), String.format("%s has intValue", jsonStr));
    assertTrue(jsonStr.contains("\"shortValue\":200"), String.format("%s has shortValue", jsonStr));
    assertTrue(jsonStr.contains("\"byteValue\":8"), String.format("%s has byteValue", jsonStr));
    assertTrue(
        jsonStr.contains("\"byteArray\":\"dHJv\""),
        String.format("%s has byteArray", jsonStr)
    );
    assertTrue(jsonStr.contains("\"boolValue\":true"), String.format("%s has boolValue", jsonStr));
  }

  @Test
  void testFromJsonText() {
    final var jsonStr = "{\"strValue\":\"test\",\"intValue\":1000,\"shortValue\":50,\"byteValue\":0,\"byteArray\":\"dHJv\",\"boolValue\":true}";
    final var sample = JsonUtils.fromJson(jsonStr, Sample.class);
    assertEquals("test", sample.strValue);
    assertEquals(1000, sample.intValue);
    assertEquals((short) 50, sample.shortValue);
    assertEquals((byte) 0x0, sample.byteValue);
    assertArrayEquals(new byte[]{116, 114, 111}, sample.byteArray);
    assertTrue(sample.boolValue);
  }

  @Test
  void testFromJsonTextWhenExceptionIsNotThrown() {
    final var gson = JsonUtils.createGsonBuilder();
    final var jsonStr = "{\"strValue\":test,\"intValue\":\"1000\",\"shortValue\":\"5\",\"byteValue\":\"0\",\"byteArray\":\"\",\"boolValue\":\"true\"}";
    assertDoesNotThrow(() -> gson.fromJson(jsonStr, Sample.class));
  }

  @Test
  void testFromJsonTextWhenByteArrayIsNotBase64() {
    final var gson = JsonUtils.createGsonBuilder();
    final var jsonStr = "{\"strValue\":\"test\",\"intValue\":1000,\"shortValue\":5,\"byteValue\":0,\"byteArray\":[116, 114, 111],\"boolValue\":true}";
    assertThrows(JsonSyntaxException.class, () -> gson.fromJson(jsonStr, Sample.class));
  }

  @Test
  void testFromJsonFile() {
    // TODO
    assertTrue(true);
  }

  private static class Sample {

    private final String strValue;
    private final int intValue;
    private final short shortValue;
    private final byte byteValue;
    private final byte[] byteArray;
    private final boolean boolValue;

    private Sample() {
      this("sample", 10000, (short) 200, (byte) 0x8, new byte[]{116, 114, 111}, true);
    }

    private Sample(final String strValue, final int intValue, final short shortValue,
        final byte byteValue, final byte[] byteArray, final boolean boolValue) {
      this.strValue = strValue;
      this.intValue = intValue;
      this.shortValue = shortValue;
      this.byteValue = byteValue;
      this.byteArray = byteArray;
      this.boolValue = boolValue;
    }
  }
}
