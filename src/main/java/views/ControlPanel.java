package views;

import controllers.CrawlController.CrawlHelper;
import java.awt.Component;
import java.awt.Dimension;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JPanel;

/**
 * データのインポートやエクスポート等の操作ボタンを配置するコンポーネント。
 */
public class ControlPanel extends JPanel {

  public static final int WIDTH = 100;

  public ControlPanel(final CrawlHelper crawlHelper) {
    setLayout(new BoxLayout(this, BoxLayout.PAGE_AXIS));

    final var addEmptyLogEntryButton = new JButton("空行追加");
    addEmptyLogEntryButton.addActionListener(e -> crawlHelper.addEmptyLogEntry());
    addEmptyLogEntryButton.setAlignmentX(Component.CENTER_ALIGNMENT);
    add(addEmptyLogEntryButton);

    final var renumberButton = new JButton("No振り直し");
    renumberButton.addActionListener(e -> crawlHelper.renumber());
    renumberButton.setAlignmentX(Component.CENTER_ALIGNMENT);
    add(renumberButton);

    final var applyDuplicatedRequestButton = new JButton("重複判定");
    applyDuplicatedRequestButton.addActionListener(e -> crawlHelper.applyDuplicatedRequest());
    applyDuplicatedRequestButton.setAlignmentX(Component.CENTER_ALIGNMENT);
    add(applyDuplicatedRequestButton);

    final var importCrawledDataButton = new JButton("JSON追加");
    importCrawledDataButton.addActionListener(e -> crawlHelper.importCrawledData());
    importCrawledDataButton.setAlignmentX(Component.CENTER_ALIGNMENT);
    add(importCrawledDataButton);

    final var exportCrawledDataButton = new JButton("JSON出力");
    exportCrawledDataButton.addActionListener(e -> crawlHelper.exportCrawledData());
    exportCrawledDataButton.setAlignmentX(Component.CENTER_ALIGNMENT);
    add(exportCrawledDataButton);

    setPreferredSize(new Dimension(WIDTH, Integer.MAX_VALUE));
  }
}
