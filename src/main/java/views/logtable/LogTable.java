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
    setTransferHandler(new LogTableRowTransferHandler());
    setDropMode(DropMode.INSERT_ROWS);
    setDragEnabled(true);
    setFillsViewportHeight(true);
  }

  @Override
  public Component prepareRenderer(final TableCellRenderer renderer, final int rowIndex,
      final int columnIndex) {
    final var component = super.prepareRenderer(renderer, rowIndex, columnIndex);
    final var selectedRows = getSelectedRows();

    if (Arrays.stream(selectedRows).anyMatch(r -> r == rowIndex)) {
      component.setBackground(getSelectionBackground());
      component.setForeground(getSelectionForeground());
      return component;
    }

    component.setForeground(getForeground());
    component.setBackground(getBackground());
    return component;
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

      final var modelRowIndex = convertRowIndexToModel(selectedRowIndex);
      final var logEntry = getModel().getLogEntryAt(modelRowIndex);
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

    final var modelRowIndex = convertRowIndexToModel(rowIndex);
    final var modelColumnIndex = convertColumnIndexToModel(columnIndex);
    if (!getModel().getLogEntryKey(modelColumnIndex).hasTooltip()) {
      return null;
    }

    final var text = getModel().getValueAt(modelRowIndex, modelColumnIndex).toString();
    final var chunks = text.split("(?<=\\G.{100})");
    return String.join("\n", chunks);
  }

  public int[] getSelectedModelIndices() {
    return Arrays.stream(getSelectedRows())
        .map(this::convertRowIndexToModel)
        .sorted()
        .toArray();
  }

  public String selectionsToString() {
    final var columns = Arrays.stream(getSelectedColumns())
        .map(this::convertColumnIndexToModel)
        .toArray();

    final IntFunction<String> rowToString = i ->
        Arrays.stream(columns).mapToObj(j -> getValueAt(i, j))
            .filter(Objects::nonNull)
            .map(Object::toString)
            .collect(Collectors.joining("\t"));

    return Arrays.stream(getSelectedRows())
        .map(this::convertRowIndexToModel)
        .mapToObj(rowToString)
        .collect(Collectors.joining("\n"));
  }
}
