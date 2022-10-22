package views;

import controllers.CrawlController;
import controllers.CrawlProxyController;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.util.List;
import javax.swing.BorderFactory;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JPanel;
import javax.swing.JTextField;
import javax.swing.JToggleButton;
import views.listeners.UpdateDocumentListener;

/**
 * データのインポートやエクスポート等の操作ボタンを配置するコンポーネント。
 */
public class ControlPanel extends JPanel {

  public static final int WIDTH = 110;

  public ControlPanel(final CrawlController crawlController) {
    final var crawlHelper = crawlController.getHelper();
    final var proxyController = crawlController.getProxyController();

    final var addEmptyLogEntryButton = new JButton("空行追加");
    addEmptyLogEntryButton.addActionListener(e -> crawlHelper.addEmptyLogEntry());
    addEmptyLogEntryButton.setAlignmentX(Component.CENTER_ALIGNMENT);

    final var renumberButton = new JButton("No振り直し");
    renumberButton.addActionListener(e -> crawlHelper.renumber());
    renumberButton.setAlignmentX(Component.CENTER_ALIGNMENT);

    final var applyRequestNameHashButton = new JButton("ハッシュ付与");
    applyRequestNameHashButton.setToolTipText("連続した同名リクエスト名にハッシュを付与する");
    applyRequestNameHashButton.addActionListener(e -> crawlHelper.applyRequestNameHash());
    applyRequestNameHashButton.setAlignmentX(Component.CENTER_ALIGNMENT);

    final var applyDuplicatedRequestButton = new JButton("重複判定");
    applyDuplicatedRequestButton.addActionListener(e -> crawlHelper.applyDuplicatedRequest());
    applyDuplicatedRequestButton.setAlignmentX(Component.CENTER_ALIGNMENT);

    final var importCrawledDataButton = new JButton("JSON追加");
    importCrawledDataButton.addActionListener(e -> crawlHelper.importCrawledData());
    importCrawledDataButton.setAlignmentX(Component.CENTER_ALIGNMENT);

    final var exportCrawledDataButton = new JButton("JSON出力");
    exportCrawledDataButton.addActionListener(e -> crawlHelper.exportCrawledData());
    exportCrawledDataButton.setAlignmentX(Component.CENTER_ALIGNMENT);

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

    final var scopeOnlyCheckBox = new JCheckBox("スコープ内のみ");
    scopeOnlyCheckBox.addChangeListener(e -> {
      final var checkBox = (JCheckBox) e.getSource();
      proxyController.setOnlyInScope(checkBox.isSelected());
    });
    scopeOnlyCheckBox.setAlignmentX(Component.CENTER_ALIGNMENT);

    final var excludedPanel = createExcludedPanel(proxyController);

    setLayout(new GridBagLayout());
    final var gbc = new GridBagConstraints();
    gbc.fill = GridBagConstraints.HORIZONTAL;
    gbc.gridx = 0;
    gbc.gridy = 0;
    gbc.weightx = 1;
    gbc.weighty = 0;
    gbc.insets = new Insets(10, 5, 0, 5);
    add(addEmptyLogEntryButton, gbc);
    gbc.gridy++;
    gbc.insets = new Insets(5, 5, 0, 5);
    add(renumberButton, gbc);
    gbc.gridy++;
    add(applyRequestNameHashButton, gbc);
    gbc.gridy++;
    add(applyDuplicatedRequestButton, gbc);
    gbc.gridy++;
    gbc.insets = new Insets(30, 5, 0, 5);
    add(importCrawledDataButton, gbc);
    gbc.gridy++;
    gbc.insets = new Insets(5, 5, 0, 5);
    add(exportCrawledDataButton, gbc);
    gbc.gridy++;
    gbc.insets = new Insets(100, 5, 0, 5);
    add(crawlProxyToggle, gbc);
    gbc.gridy++;
    gbc.insets = new Insets(5, 5, 10, 5);
    add(scopeOnlyCheckBox, gbc);
    gbc.gridy++;
    gbc.insets = new Insets(5, 5, 0, 5);
    add(excludedPanel, gbc);
    gbc.gridy++;
    gbc.weighty = 1;
    add(new JPanel(), gbc);

    setPreferredSize(new Dimension(WIDTH, Integer.MAX_VALUE));
  }

  private JPanel createExcludedPanel(final CrawlProxyController proxyController) {
    final var excludedMimeCheckBox = new JCheckBox("MIME");
    excludedMimeCheckBox.addChangeListener(e -> {
      final var checkBox = (JCheckBox) e.getSource();
      proxyController.useExcludedMime(checkBox.isSelected());
    });

    final var excludedMimeTextField = new JTextField(50);
    final var excludedMimeListener = (UpdateDocumentListener) e -> {
      final var mimeList = excludedMimeTextField.getText().split(",");
      proxyController.setExcludedMime(List.of(mimeList));
    };
    excludedMimeTextField.getDocument().addDocumentListener(excludedMimeListener);

    final var excludedExtensionsCheckBox = new JCheckBox("拡張子");
    excludedExtensionsCheckBox.addChangeListener(e -> {
      final var checkBox = (JCheckBox) e.getSource();
      proxyController.useExcludedExtensions(checkBox.isSelected());
    });

    final var excludedExtensionsTextField = new JTextField(50);
    final var excludedExtensionsListener = (UpdateDocumentListener) e -> {
      final var extensionList = excludedExtensionsTextField.getText().split(",");
      proxyController.setExcludedExtensions(List.of(extensionList));
    };
    excludedExtensionsTextField.getDocument().addDocumentListener(excludedExtensionsListener);

    final var excludedPanel = new JPanel();
    excludedPanel.setBorder(BorderFactory.createTitledBorder("対象外"));
    excludedPanel.setLayout(new BoxLayout(excludedPanel, BoxLayout.PAGE_AXIS));
    excludedPanel.add(excludedMimeCheckBox);
    excludedPanel.add(excludedMimeTextField);
    excludedPanel.add(excludedExtensionsCheckBox);
    excludedPanel.add(excludedExtensionsTextField);

    return excludedPanel;
  }
}
