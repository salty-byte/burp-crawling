package models.json;

import java.util.List;
import java.util.stream.Collectors;
import models.LogEntry;

public class CrawledData {

  private final String crawling;
  private final List<LogEntryForJson> entries;

  public CrawledData(final List<LogEntry> entries) {
    this.entries = entries.stream()
        .map(LogEntryForJson::new)
        .collect(Collectors.toList());
    crawling = "1.0";
  }

  public String getVersion() {
    return crawling;
  }

  public List<LogEntryForJson> getEntries() {
    return entries;
  }

  public List<LogEntry> toLogEntries() {
    return entries.stream()
        .map(LogEntry::new)
        .collect(Collectors.toList());
  }
}
