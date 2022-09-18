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
    final var dummyButton3 = new JButton("Dummy");
    dummyButton1.setAlignmentX(Component.CENTER_ALIGNMENT);
    dummyButton2.setAlignmentX(Component.CENTER_ALIGNMENT);
    dummyButton3.setAlignmentX(Component.CENTER_ALIGNMENT);
    add(dummyButton1);
    add(dummyButton2);
    add(dummyButton3);

    final var addEmptyLogEntryButton = new JButton("空行追加");
    addEmptyLogEntryButton.addActionListener(e -> crawlHelper.addEmptyLogEntry());
    addEmptyLogEntryButton.setAlignmentX(Component.CENTER_ALIGNMENT);
    add(addEmptyLogEntryButton);

    setPreferredSize(new Dimension(WIDTH, Integer.MAX_VALUE));
  }
}
