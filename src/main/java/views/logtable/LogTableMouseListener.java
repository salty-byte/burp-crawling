package views.logtable;

import controllers.CrawlHelper;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import javax.swing.SwingUtilities;

public class LogTableMouseListener extends MouseAdapter {

  private final CrawlHelper crawlHelper;
  private final LogTable logTable;

  public LogTableMouseListener(final CrawlHelper crawlHelper, final LogTable logTable) {
    this.crawlHelper = crawlHelper;
    this.logTable = logTable;
  }

  @Override
  public void mouseClicked(final MouseEvent event) {
    showPopupMenu(event);
  }

  private void showPopupMenu(final MouseEvent event) {
    final var indices = logTable.getSelectedModelIndices();
    final var entries = logTable.getModel().getLogEntriesAt(indices);
    if (!SwingUtilities.isRightMouseButton(event) || entries.isEmpty()) {
      return;
    }

    final var popupMenu = new LogTablePopupMenu(crawlHelper, entries, indices);
    popupMenu.show(logTable, event.getX(), event.getY());
  }
}
