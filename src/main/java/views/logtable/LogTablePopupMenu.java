package views.logtable;

import controllers.CrawlController.CrawlHelper;
import java.awt.Component;
import java.util.List;
import javax.swing.JMenuItem;
import javax.swing.JPopupMenu;
import models.LogEntry;

public class LogTablePopupMenu extends JPopupMenu {

  public LogTablePopupMenu(final CrawlHelper crawlHelper, final List<LogEntry> logEntries) {
    final var removeLogEntriesItem = new JMenuItem("行削除");
    removeLogEntriesItem.addActionListener(e -> crawlHelper.removeLogEntries(logEntries));
    removeLogEntriesItem.setAlignmentX(Component.CENTER_ALIGNMENT);
    add(removeLogEntriesItem);
  }
}
