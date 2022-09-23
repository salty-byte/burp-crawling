package views.logtable;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
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

  public List<LogEntry> getLogEntryAll() {
    return entries;
  }

  public LogEntry getLogEntryAt(final int index) {
    return entries.get(index);
  }

  public List<LogEntry> getLogEntriesAt(final int[] indices) {
    return Arrays.stream(indices)
        .distinct()
        .mapToObj(this::getLogEntryAt)
        .collect(Collectors.toList());
  }

  public void addLogEntry(final LogEntry logEntry) {
    addLogEntryAt(logEntry, entries.size());
  }

  public void addLogEntryAt(final LogEntry logEntry, final int index) {
    entries.add(index, logEntry);
    fireTableRowsInserted(index, index);
  }

  public void addLogEntries(final List<LogEntry> logEntries) {
    addLogEntriesAt(logEntries, entries.size());
  }

  public void addLogEntriesAt(final List<LogEntry> logEntries, final int index) {
    entries.addAll(index, logEntries);
    fireTableRowsInserted(index, index + logEntries.size() - 1);
  }

  public void removeLogEntryAt(final int index) {
    entries.remove(index);
    fireTableRowsDeleted(index, index);
  }

  public void removeLogEntriesAt(final int[] indices) {
    Arrays.stream(indices)
        .distinct()
        .boxed()
        .sorted(Comparator.reverseOrder())
        .forEachOrdered(this::removeLogEntryAt);
  }

  public void renumber() {
    if (entries.isEmpty()) {
      return;
    }

    int count = 0;
    for (final var entry : entries) {
      entry.setNumber(++count);
    }
    updateAllRows();
  }

  public void updateAllRows() {
    fireTableRowsUpdated(0, entries.size() - 1);
  }
}
