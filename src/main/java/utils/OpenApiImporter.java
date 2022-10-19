package utils;

import exceptions.CrawlException;
import io.swagger.parser.OpenAPIParser;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import models.LogEntry;

public class OpenApiImporter {

  private OpenApiImporter() {
    throw new IllegalStateException("Utility class");
  }

  public static List<LogEntry> parse(final Path file) throws CrawlException, IOException {
    final var contents = Files.readString(file);
    return parse(contents);
  }

  public static List<LogEntry> parse(final String contents) throws CrawlException {
    final var result = new OpenAPIParser().readContents(contents, null, null);
    if (!result.getMessages().isEmpty()) {
      throw new CrawlException("OpenAPI parse error: " + String.join(",", result.getMessages()));
    }

    final var openApi = result.getOpenAPI();
    if (openApi == null) {
      return new ArrayList<>();
    }

    final var logEntries = new ArrayList<LogEntry>();
    for (final var itemSet : openApi.getPaths().entrySet()) {
      final var path = itemSet.getKey();
      final var item = itemSet.getValue();

      for (final var operationSet : item.readOperationsMap().entrySet()) {
        final var method = operationSet.getKey().name();
        final var summary = operationSet.getValue().getSummary();
        final var description = operationSet.getValue().getDescription();
        final var logEntry = new LogEntry(logEntries.size() + 1);
        logEntry.setRequestName(summary);
        logEntry.setUrl(path);
        logEntry.setMethod(method);
        logEntry.setRemark(description);
        logEntries.add(logEntry);
      }
    }
    return logEntries;
  }
}
