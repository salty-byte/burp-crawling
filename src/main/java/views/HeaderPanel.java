package views;

import java.awt.Component;
import java.awt.Dimension;
import javax.swing.BoxLayout;
import javax.swing.JLabel;
import javax.swing.JPanel;

public class HeaderPanel extends JPanel {

  public static final int HEIGHT = 50;

  /**
   * TODO 操作機能を追加する
   */
  public HeaderPanel() {
    setLayout(new BoxLayout(this, BoxLayout.LINE_AXIS));
    final var dummyLabel = new JLabel("Dummy Header");
    dummyLabel.setAlignmentX(Component.CENTER_ALIGNMENT);
    add(dummyLabel);
    setPreferredSize(new Dimension(Integer.MAX_VALUE, HEIGHT));
  }
}
