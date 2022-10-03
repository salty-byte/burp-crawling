package views.logtable;

import controllers.LogDetailController;
import java.awt.Component;
import java.awt.event.MouseEvent;
import java.util.Arrays;
import java.util.Objects;
import java.util.function.IntFunction;
import java.util.stream.Collectors;
import javax.swing.DropMode;
import javax.swing.JTable;
import javax.swing.ListSelectionModel;
import javax.swing.table.TableCellRenderer;
import models.LogEntry;
import models.LogEntryKey;

public class LogTable extends JTable {

  public static final int DEFAULT_HEIGHT = 600;

  public LogTable(final LogTableModel logTableModel,
      final LogDetailController logDetailController) {
    super(logTableModel);
    setAutoResizeMode(JTable.AUTO_RESIZE_OFF);
    setRowHeight(20);
    Arrays.stream(LogEntryKey.values())
        .forEach(v -> getColumn(v.getDisplayName()).setPreferredWidth(v.getWidth()));
    setSelectionListener(logDetailController);
    setRowSorter(new LogTableRowSorter<>(getModel()));

    // settings to drag and drop some rows
    setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
    setTransferHandler(new LogTableTransferHandler());
    setDropMode(DropMode.INSERT_ROWS);
    setDragEnabled(true);
    setFillsViewportHeight(true);
  }

  @Override
  public Component prepareRenderer(final TableCellRenderer renderer, final int rowIndex,
      final int columnIndex) {
    final var component = super.prepareRenderer(renderer, rowIndex, columnIndex);
    final var selectedRows = getSelectedRows();
    final var colorType = getLogEntryAt(rowIndex).getColorType();

    if (Arrays.stream(selectedRows).anyMatch(r -> r == rowIndex)) {
      final var background = colorType.getSelectionBackground();
      final var foreground = colorType.getSelectionForeground();
      final var nextBackground = background == null ? getSelectionBackground() : background;
      final var nextForeground = foreground == null ? getSelectionForeground() : foreground;
      component.setBackground(nextBackground);
      component.setForeground(nextForeground);
      return component;
    }

    component.setBackground(colorType.getBackground());
    component.setForeground(colorType.getForeground());
    return component;
  }

  @Override
  public boolean isCellEditable(int rowIndex, int columnIndex) {
    final var modelColumnIndex = convertColumnIndexToModel(columnIndex);
    return getLogEntryKeyAt(modelColumnIndex).isEditable();
  }

  private void setSelectionListener(final LogDetailController logDetailController) {
    getSelectionModel().addListSelectionListener(e -> {
      if (e.getValueIsAdjusting()) {
        return;
      }

      final var selectedRowIndex = getSelectedRow();
      if (selectedRowIndex == -1) {
        logDetailController.clear();
        return;
      }

      final var logEntry = getLogEntryAt(selectedRowIndex);
      logDetailController.setMessages(logEntry);
    });
  }

  @Override
  public LogTableModel getModel() {
    return (LogTableModel) super.getModel();
  }

  @Override
  public String getToolTipText(final MouseEvent e) {
    final var point = e.getPoint();
    final var rowIndex = rowAtPoint(point);
    final var columnIndex = columnAtPoint(point);
    if (rowIndex == -1 || columnIndex == -1) {
      return null;
    }

    if (!getLogEntryKeyAt(columnIndex).hasTooltip()) {
      return null;
    }

    final var text = getValueAt(rowIndex, columnIndex).toString();
    final var chunks = text.split("(?<=\\G.{100})");
    return String.join("\n", chunks);
  }

  public LogEntry getLogEntryAt(final int rowIndex) {
    final var modelRowIndex = convertRowIndexToModel(rowIndex);
    return getModel().getLogEntryAt(modelRowIndex);
  }

  public LogEntryKey getLogEntryKeyAt(final int columnIndex) {
    final var modelColumnIndex = convertColumnIndexToModel(columnIndex);
    return getModel().getLogEntryKey(modelColumnIndex);
  }

  public int[] getSelectedModelIndices() {
    return Arrays.stream(getSelectedRows())
        .map(this::convertRowIndexToModel)
        .sorted()
        .toArray();
  }

  public String selectionsToString() {
    final var columns = getSelectedColumns();

    final IntFunction<String> rowToString = i ->
        Arrays.stream(columns).mapToObj(j -> getValueAt(i, j))
            .map(v -> Objects.toString(v, ""))
            .collect(Collectors.joining("\t"));

    return Arrays.stream(getSelectedRows())
        .mapToObj(rowToString)
        .collect(Collectors.joining("\n"));
  }

  public void pasteToSelectedCells(final String data) {
    if (data == null || data.isEmpty()) {
      return;
    }

    final var columns = getSelectedColumns();
    final var rows = getSelectedRows();
    final var lines = data.split("\n");
    for (int i = 0; i < lines.length && i < rows.length; i++) {
      final var values = lines[i].split("\t");
      for (int j = 0; j < values.length && j < columns.length; j++) {
        final var logEntryKey = getLogEntryKeyAt(columns[j]);
        if (logEntryKey.isEditable()) {
          final var value = logEntryKey.parseFromString(values[j]);
          setValueAt(value, rows[i], columns[j]);
        }
      }
    }
  }

  public int calcInsertIndex(final int index) {
    final int maxIndex = getRowCount();
    return index < 0 ? maxIndex : Math.min(index, maxIndex);
  }
}
