package views.logtable;

import controllers.CrawlController;
import controllers.LogDetailController;
import java.awt.Component;
import java.util.Arrays;
import javax.swing.DropMode;
import javax.swing.JTable;
import javax.swing.ListSelectionModel;
import javax.swing.table.TableCellRenderer;
import models.LogEntryKey;

public class LogTable extends JTable {

  public static final int DEFAULT_HEIGHT = 600;

  public LogTable(final CrawlController crawlController) {
    super(crawlController.getLogTableModel());
    setAutoResizeMode(JTable.AUTO_RESIZE_OFF);
    setRowHeight(20);
    Arrays.stream(LogEntryKey.values())
        .forEach(v -> this.getColumn(v.getDisplayName()).setPreferredWidth(v.getWidth()));
    setSelectionListener(crawlController.getLogDetailController());
    setRowSorter(new LogTableRowSorter<>(getModel()));

    // settings to drag and drop some rows
    setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
    setTransferHandler(new LogTableRowTransferHandler());
    setDropMode(DropMode.INSERT_ROWS);
    setDragEnabled(true);
    setFillsViewportHeight(true);
  }

  @Override
  public Component prepareRenderer(TableCellRenderer renderer, int rowIndex, int columnIndex) {
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

      final var selectedRow = getSelectedRow();
      if (selectedRow == -1) {
        logDetailController.clear();
        return;
      }

      final var modelRow = convertRowIndexToModel(selectedRow);
      final var logEntry = getModel().getLogEntryAt(modelRow);
      logDetailController.setMessages(logEntry);
    });
  }

  @Override
  public LogTableModel getModel() {
    return (LogTableModel) super.getModel();
  }
}
