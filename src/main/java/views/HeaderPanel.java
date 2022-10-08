package views;

import controllers.CrawlProxyController;
import java.awt.Dimension;
import java.awt.FlowLayout;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTextField;
import views.listeners.UpdateDocumentListener;

public class HeaderPanel extends JPanel {

  public static final int HEIGHT = 45;

  HeaderPanel(final CrawlProxyController proxyController) {
    setLayout(new FlowLayout(FlowLayout.LEFT, 10, 10));

    final var requestBaseLabel = new JLabel("リクエスト名：");
    final var requestBaseNameField = new JTextField(50);
    final var requestBasePartitionLabel = new JLabel(">");
    final var requestLinkNameField = new JTextField(25);
    final var requestNameUpdateButton = new JButton("追加");
    final var requestLinkNameResetButton = new JButton("リセット");
    final var listener = (UpdateDocumentListener) e -> {
      final var base = requestBaseNameField.getText();
      final var name = requestLinkNameField.getText();
      final var requestName = name.isEmpty() ? base : String.format("%s>%s", base, name);
      proxyController.setRequestName(requestName);
    };
    requestBaseNameField.getDocument().addDocumentListener(listener);
    requestLinkNameField.getDocument().addDocumentListener(listener);
    requestNameUpdateButton.addActionListener(e -> {
      final var base = requestBaseNameField.getText();
      final var name = requestLinkNameField.getText();
      final var requestName = name.isEmpty() ? base : String.format("%s>%s", base, name);
      requestBaseNameField.setText(requestName);
      requestLinkNameField.setText("");
    });
    requestLinkNameResetButton.addActionListener(e -> requestLinkNameField.setText(""));
    add(requestBaseLabel);
    add(requestBaseNameField);
    add(requestBasePartitionLabel);
    add(requestLinkNameField);
    add(requestNameUpdateButton);
    add(requestLinkNameResetButton);

    setPreferredSize(new Dimension(Integer.MAX_VALUE, HEIGHT));
  }
}
