package utils;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import exceptions.CrawlException;
import java.io.File;
import org.junit.jupiter.api.Test;

class OpenApiImporterTest {

  @Test
  void testParseWithV3Yaml() throws Exception {
    final var resource = getClass().getResource("/openapi/openapi-v3.yaml");
    assertNotNull(resource);

    final var file = new File(resource.getFile());
    final var result = OpenApiImporter.parse(file);
    assertEquals(3, result.size());

    final var logEntry1 = result.get(0);
    assertEquals(1, logEntry1.getNumber());
    assertEquals("List all pets", logEntry1.getRequestName());
    assertEquals("GET", logEntry1.getMethod());
    assertEquals("/pets", logEntry1.getUrl());

    final var logEntry2 = result.get(1);
    assertEquals(2, logEntry2.getNumber());
    assertEquals("Create a pet", logEntry2.getRequestName());
    assertEquals("POST", logEntry2.getMethod());
    assertEquals("/pets", logEntry2.getUrl());

    final var logEntry3 = result.get(2);
    assertEquals(3, logEntry3.getNumber());
    assertEquals("Info for a specific pet", logEntry3.getRequestName());
    assertEquals("GET", logEntry3.getMethod());
    assertEquals("/pets/{petId}", logEntry3.getUrl());
  }

  @Test
  void testParseWithV3Json() throws Exception {
    final var resource = getClass().getResource("/openapi/openapi-v3.json");
    assertNotNull(resource);

    final var file = new File(resource.getFile());
    final var result = OpenApiImporter.parse(file);
    assertEquals(19, result.size());

    final var logEntry1 = result.get(0);
    assertEquals(1, logEntry1.getNumber());
    assertEquals("Update an existing pet", logEntry1.getRequestName());
    assertEquals("PUT", logEntry1.getMethod());
    assertEquals("/pet", logEntry1.getUrl());

    final var logEntry2 = result.get(1);
    assertEquals(2, logEntry2.getNumber());
    assertEquals("Add a new pet to the store", logEntry2.getRequestName());
    assertEquals("POST", logEntry2.getMethod());
    assertEquals("/pet", logEntry2.getUrl());

    final var logEntry3 = result.get(2);
    assertEquals(3, logEntry3.getNumber());
    assertEquals("Finds Pets by status", logEntry3.getRequestName());
    assertEquals("GET", logEntry3.getMethod());
    assertEquals("/pet/findByStatus", logEntry3.getUrl());

    final var logEntry19 = result.get(18);
    assertEquals(19, logEntry19.getNumber());
    assertEquals("Delete user", logEntry19.getRequestName());
    assertEquals("DELETE", logEntry19.getMethod());
    assertEquals("/user/{username}", logEntry19.getUrl());
  }

  @Test
  void testParseIfErrorThrown() {
    final var resource = getClass().getResource("/openapi/openapi-error.json");
    assertNotNull(resource);

    final var file = new File(resource.getFile());
    assertThrows(CrawlException.class, () -> OpenApiImporter.parse(file));
  }
}
