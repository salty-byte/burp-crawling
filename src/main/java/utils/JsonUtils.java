package utils;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.TypeAdapter;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonWriter;
import java.io.FileReader;
import java.io.IOException;
import java.util.Base64;

public class JsonUtils {

  private JsonUtils() {
    throw new IllegalStateException("Utility class");
  }

  public static Gson createGsonBuilder() {
    return new GsonBuilder()
        .registerTypeAdapter(byte[].class, new Base64TypeAdapter())
        .create();
  }

  public static String toJson(final Object obj, final Class<?> classification) {
    return createGsonBuilder().toJson(obj, classification);
  }

  public static <T> T fromJson(final String json, final Class<T> classification) {
    return createGsonBuilder().fromJson(json, classification);
  }

  public static <T> T fromJson(final FileReader reader, final Class<T> classification) {
    return createGsonBuilder().fromJson(reader, classification);
  }

  static class Base64TypeAdapter extends TypeAdapter<byte[]> {

    @Override
    public void write(JsonWriter out, byte[] value) throws IOException {
      out.value(Base64.getEncoder().withoutPadding().encodeToString(value));
    }

    @Override
    public byte[] read(JsonReader in) throws IOException {
      return Base64.getDecoder().decode(in.nextString());
    }
  }
}
