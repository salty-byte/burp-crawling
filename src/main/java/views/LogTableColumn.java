package views;

import javax.swing.table.TableColumn;
import models.LogEntryKey;

public class LogTableColumn extends TableColumn {

  public LogTableColumn(final LogEntryKey key) {
    super();
    setIdentifier(key);
  }

  public LogEntryKey getKey() {
    return (LogEntryKey) this.identifier;
  }
}
