package views;

import controllers.CrawlController;
import java.awt.Component;
import java.util.Arrays;
import javax.swing.JTable;
import javax.swing.table.TableCellRenderer;
import models.LogEntryKey;

public class LogTable extends JTable {

  public static final int DEFAULT_HEIGHT = 600;

  LogTable(final CrawlController crawlController) {
    super(crawlController.getLogTableModel());
    setAutoResizeMode(JTable.AUTO_RESIZE_OFF);
    setRowHeight(20);
    Arrays.stream(LogEntryKey.values())
        .forEach(v -> this.getColumn(v.getDisplayName()).setPreferredWidth(v.getWidth()));
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
}
