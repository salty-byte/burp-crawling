package views;

import controllers.CrawlController;
import java.util.Arrays;
import javax.swing.JTable;
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
}
