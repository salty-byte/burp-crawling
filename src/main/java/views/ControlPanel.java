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
    final var dummyButton1 = new JButton("Dummy");
    final var dummyButton2 = new JButton("Dummy");
    dummyButton1.setAlignmentX(Component.CENTER_ALIGNMENT);
    dummyButton2.setAlignmentX(Component.CENTER_ALIGNMENT);
    add(dummyButton1);
    add(dummyButton2);

    final var addEmptyLogEntryButton = new JButton("空行追加");
    addEmptyLogEntryButton.addActionListener(e -> crawlHelper.addEmptyLogEntry());
    addEmptyLogEntryButton.setAlignmentX(Component.CENTER_ALIGNMENT);
    add(addEmptyLogEntryButton);

    final var renumberButton = new JButton("No振り直し");
    renumberButton.addActionListener(e -> crawlHelper.renumber());
    renumberButton.setAlignmentX(Component.CENTER_ALIGNMENT);
    add(renumberButton);

    final var exportCrawledDataButton = new JButton("JSON出力");
    exportCrawledDataButton.addActionListener(e -> crawlHelper.exportCrawledData());
    exportCrawledDataButton.setAlignmentX(Component.CENTER_ALIGNMENT);
    add(exportCrawledDataButton);

    setPreferredSize(new Dimension(WIDTH, Integer.MAX_VALUE));
  }
}
