package models.json;

import java.util.List;
import java.util.stream.Collectors;
import models.LogEntry;

public class CrawledData {

  private final String version;
  private final List<LogEntryForJson> entries;

  public CrawledData(final List<LogEntry> entries) {
    this.entries = entries.stream()
        .map(LogEntryForJson::new)
        .collect(Collectors.toList());
    version = "1.0";
  }

  public String getVersion() {
    return version;
  }

  public List<LogEntryForJson> getEntries() {
    return entries;
  }

  public List<LogEntry> toLogEntries() {
    return entries.stream()
        .map(LogEntryForJson::toLogEntry)
        .collect(Collectors.toList());
  }
}
