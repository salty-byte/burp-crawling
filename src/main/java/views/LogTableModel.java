package views;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;
import javax.swing.table.AbstractTableModel;
import models.LogEntry;
import models.LogEntryKey;

public class LogTableModel extends AbstractTableModel {

  private final transient List<LogEntry> entries;
  private final transient List<LogTableColumn> columns;

  public LogTableModel() {
    columns = createColumns();
    entries = Collections.synchronizedList(new ArrayList<>());
  }

  private List<LogTableColumn> createColumns() {
    return Arrays.stream(LogEntryKey.values())
        .map(LogTableColumn::new)
        .collect(Collectors.toList());
  }

  @Override
  public boolean isCellEditable(int rowIndex, int columnIndex) {
    return true;
  }

  @Override
  public int getRowCount() {
    return entries.size();
  }

  @Override
  public int getColumnCount() {
    return columns.size();
  }

  @Override
  public Class<?> getColumnClass(int columnIndex) {
    return columns.get(columnIndex).getKey().getClassification();
  }

  @Override
  public String getColumnName(int columnIndex) {
    return columns.get(columnIndex).getKey().getDisplayName();
  }

  @Override
  public Object getValueAt(int rowIndex, int columnIndex) {
    return entries.get(rowIndex).getValueByKey(columns.get(columnIndex).getKey());
  }

  @Override
  public void setValueAt(Object value, int rowIndex, int columnIndex) {
    final var key = columns.get(columnIndex).getKey();
    entries.get(rowIndex).setValueByKey(key, value);
    fireTableCellUpdated(rowIndex, columnIndex);
  }

  public synchronized void addLogEntry(final LogEntry logEntry) {
    int index = entries.size();
    entries.add(logEntry);
    fireTableRowsInserted(index, index);
  }

  public void addLogEntries(final List<LogEntry> logEntries) {
    logEntries.forEach(this::addLogEntry);
  }

  public synchronized void removeLogEntryAt(final int rowIndex) {
    entries.remove(rowIndex);
    this.fireTableRowsDeleted(rowIndex, rowIndex);
  }
}
