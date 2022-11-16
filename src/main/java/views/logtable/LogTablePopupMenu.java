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

  public LogTablePopupMenu(final CrawlHelper crawlHelper, final List<LogEntry> logEntries,
      final int[] indices) {
    final var requestCount = crawlHelper.countRequest(logEntries);
    final var repeaterItem = new JMenuItem(String.format("Repeaterに送る：%s", requestCount));
    repeaterItem.addActionListener(e -> crawlHelper.sendToRepeater(logEntries));
    repeaterItem.setAlignmentX(Component.CENTER_ALIGNMENT);
    repeaterItem.setToolTipText("リクエストデータがある場合、選択箇所をRepeaterに送る");
    repeaterItem.setEnabled(requestCount != 0);
    add(repeaterItem);
    addSeparator();

    final var tsvCopyItem = new JMenuItem("TSVコピー (全て)");
    tsvCopyItem.addActionListener(e -> crawlHelper.exportToClipboardWithTsv(logEntries));
    tsvCopyItem.setAlignmentX(Component.CENTER_ALIGNMENT);
    add(tsvCopyItem);
    final var tsvCopyOnlyParametersItem = new JMenuItem("TSVコピー (パラメータ)");
    tsvCopyOnlyParametersItem.addActionListener(
        e -> crawlHelper.exportParametersToClipboardWithTsv(logEntries));
    tsvCopyOnlyParametersItem.setAlignmentX(Component.CENTER_ALIGNMENT);
    add(tsvCopyOnlyParametersItem);
    addSeparator();

    // create color menu items
    Arrays.stream(ColorType.values())
        .map(c -> {
          final var item = new JMenuItem("    色変更：" + c.getDisplayName());
          item.addActionListener(e -> crawlHelper.setLogEntriesColor(c, logEntries));
          item.setBackground(c.getBackground());
          item.setForeground(c.getForeground());
          item.setOpaque(true);
          item.setUI(new LogTablePopupMenuUI(c));
          return item;
        }).forEachOrdered(this::add);
    addSeparator();

    final var markLogEntriesItem = new JMenuItem("行移動：マーク");
    markLogEntriesItem.addActionListener(e -> crawlHelper.markLogEntries(logEntries));
    markLogEntriesItem.setAlignmentX(Component.CENTER_ALIGNMENT);
    add(markLogEntriesItem);
    final var moveUpMarkedLogEntriesItem = new JMenuItem("行移動：一つ上");
    moveUpMarkedLogEntriesItem.addActionListener(
        e -> crawlHelper.moveMarkedLogEntriesAt(indices[0]));
    moveUpMarkedLogEntriesItem.setAlignmentX(Component.CENTER_ALIGNMENT);
    add(moveUpMarkedLogEntriesItem);
    final var moveDownMarkedLogEntriesItem = new JMenuItem("行移動：一つ下");
    moveDownMarkedLogEntriesItem.addActionListener(
        e -> crawlHelper.moveMarkedLogEntriesAt(indices[0] + 1));
    moveDownMarkedLogEntriesItem.setAlignmentX(Component.CENTER_ALIGNMENT);
    add(moveDownMarkedLogEntriesItem);
    crawlHelper.updateMarkedLogEntries();
    if (!crawlHelper.hasMarkedLogEntries()) {
      moveUpMarkedLogEntriesItem.setEnabled(false);
      moveDownMarkedLogEntriesItem.setEnabled(false);
    }
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
