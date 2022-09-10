package views;

import controllers.LogDetailController;
import java.awt.BorderLayout;
import java.awt.Dimension;
import javax.swing.JPanel;
import javax.swing.JSplitPane;

public class LogDetailPanel extends JPanel {

  public static final int HEIGHT = 500;

  public LogDetailPanel(final LogDetailController logDetailController) {
    final var requestEditorComponent = logDetailController.getRequestEditor().getComponent();
    final var responseEditorComponent = logDetailController.getResponseEditor().getComponent();

    final var splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
    splitPane.setLeftComponent(requestEditorComponent);
    splitPane.setRightComponent(responseEditorComponent);

    setPreferredSize(new Dimension(Integer.MAX_VALUE, HEIGHT));
    setLayout(new BorderLayout());
    add(splitPane, BorderLayout.CENTER);
    splitPane.setResizeWeight(0.5);
  }
}
