package views;

import controllers.CrawlController;
import java.awt.Component;
import java.awt.Dimension;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JPanel;
import javax.swing.JToggleButton;

/**
 * データのインポートやエクスポート等の操作ボタンを配置するコンポーネント。
 */
public class ControlPanel extends JPanel {

  public static final int WIDTH = 100;

  public ControlPanel(final CrawlController crawlController) {
    final var crawlHelper = crawlController.getHelper();
    final var proxyController = crawlController.getProxyController();
    setLayout(new BoxLayout(this, BoxLayout.PAGE_AXIS));

    final var addEmptyLogEntryButton = new JButton("空行追加");
    addEmptyLogEntryButton.addActionListener(e -> crawlHelper.addEmptyLogEntry());
    addEmptyLogEntryButton.setAlignmentX(Component.CENTER_ALIGNMENT);
    add(addEmptyLogEntryButton);

    final var removeLogEntriesButton = new JButton("行削除");
    removeLogEntriesButton.addActionListener(e -> crawlHelper.removeLogEntries());
    removeLogEntriesButton.setAlignmentX(Component.CENTER_ALIGNMENT);
    add(removeLogEntriesButton);

    final var renumberButton = new JButton("No振り直し");
    renumberButton.addActionListener(e -> crawlHelper.renumber());
    renumberButton.setAlignmentX(Component.CENTER_ALIGNMENT);
    add(renumberButton);

    final var applyRequestNameHashButton = new JButton("リクエスト名ハッシュ付与");
    applyRequestNameHashButton.setToolTipText("リクエスト名ハッシュ付与");
    applyRequestNameHashButton.addActionListener(e -> crawlHelper.applyRequestNameHash());
    applyRequestNameHashButton.setAlignmentX(Component.CENTER_ALIGNMENT);
    add(applyRequestNameHashButton);

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

    add(Box.createRigidArea(new Dimension(0, 200)));

    final var crawlProxyToggle = new JToggleButton("Proxy OFF");
    crawlProxyToggle.addChangeListener(e -> {
      final var toggle = (JToggleButton) e.getSource();
      if (toggle.isSelected()) {
        toggle.setText("Proxy ON");
        proxyController.enable();
      } else {
        toggle.setText("Proxy OFF");
        proxyController.disable();
      }
    });
    crawlProxyToggle.setAlignmentX(Component.CENTER_ALIGNMENT);
    add(crawlProxyToggle);

    final var scopeOnlyCheckBox = new JCheckBox("スコープ内のみ");
    scopeOnlyCheckBox.addChangeListener(e -> {
      final var checkBox = (JCheckBox) e.getSource();
      proxyController.setOnlyInScope(checkBox.isSelected());
    });
    scopeOnlyCheckBox.setAlignmentX(Component.CENTER_ALIGNMENT);
    add(scopeOnlyCheckBox);

    setPreferredSize(new Dimension(WIDTH, Integer.MAX_VALUE));
  }
}
