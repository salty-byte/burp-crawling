package views;

import controllers.CrawlProxyController;
import java.awt.Dimension;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTextField;
import views.listeners.UpdateDocumentListener;

public class HeaderPanel extends JPanel {

  public static final int HEIGHT = 45;

  HeaderPanel(final CrawlProxyController proxyController) {
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

    setLayout(new GridBagLayout());
    final var gbc = new GridBagConstraints();
    gbc.fill = GridBagConstraints.BOTH;
    gbc.gridx = 0;
    gbc.weightx = 0;
    gbc.weighty = 0;
    gbc.insets = new Insets(0, 10, 0, 5);
    add(requestBaseLabel, gbc);
    gbc.gridx++;
    gbc.weightx = 4;
    gbc.insets = new Insets(0, 0, 0, 5);
    add(requestBaseNameField, gbc);
    gbc.gridx++;
    gbc.weightx = 0;
    add(requestBasePartitionLabel, gbc);
    gbc.gridx++;
    gbc.weightx = 3;
    add(requestLinkNameField, gbc);
    gbc.gridx++;
    gbc.weightx = 0;
    add(requestNameUpdateButton, gbc);
    gbc.gridx++;
    gbc.insets = new Insets(0, 0, 0, 10);
    add(requestLinkNameResetButton, gbc);

    setPreferredSize(new Dimension(Integer.MAX_VALUE, HEIGHT));
  }
}
