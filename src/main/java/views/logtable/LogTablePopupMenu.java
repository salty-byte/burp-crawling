package views.logtable;

import controllers.CrawlHelper;
import java.awt.Component;
import java.util.Arrays;
import java.util.List;
import javax.swing.JMenuItem;
import javax.swing.JPopupMenu;
import javax.swing.plaf.basic.BasicMenuItemUI;
import models.ColorType;
import models.LogEntry;

public class LogTablePopupMenu extends JPopupMenu {

  public LogTablePopupMenu(final CrawlHelper crawlHelper, final List<LogEntry> logEntries) {
    final var tsvCopyItem = new JMenuItem("TSVコピー");
    tsvCopyItem.addActionListener(e -> crawlHelper.exportToClipboardWithTsv(logEntries));
    tsvCopyItem.setAlignmentX(Component.CENTER_ALIGNMENT);
    add(tsvCopyItem);
    addSeparator();

    // create color menu items
    Arrays.stream(ColorType.values())
        .map(c -> {
          final var item = new JMenuItem("色変更：" + c.getDisplayName());
          item.addActionListener(e -> crawlHelper.setLogEntriesColor(c, logEntries));
          item.setBackground(c.getBackground());
          item.setForeground(c.getForeground());
          item.setOpaque(true);
          item.setUI(new LogTablePopupMenuUI(c));
          return item;
        }).forEachOrdered(this::add);
    addSeparator();

    final var removeLogEntriesItem = new JMenuItem("行削除");
    removeLogEntriesItem.addActionListener(e -> crawlHelper.removeLogEntries(logEntries));
    removeLogEntriesItem.setAlignmentX(Component.CENTER_ALIGNMENT);
    add(removeLogEntriesItem);
  }

  private static class LogTablePopupMenuUI extends BasicMenuItemUI {

    public LogTablePopupMenuUI(final ColorType colorType) {
      super.selectionBackground = colorType.getSelectionBackground();
      super.selectionForeground = colorType.getSelectionForeground();
    }
  }
}
