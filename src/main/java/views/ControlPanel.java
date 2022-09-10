package views;

import java.awt.Component;
import java.awt.Dimension;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JPanel;

public class ControlPanel extends JPanel {

  public static final int WIDTH = 100;

  /**
   * TODO 操作用ボタンを追加する
   */
  public ControlPanel() {
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
    setPreferredSize(new Dimension(WIDTH, Integer.MAX_VALUE));
  }
}
