package views;

import controllers.LogDetailController;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import javax.swing.JPanel;
import javax.swing.JSplitPane;

public class LogDetailPanel extends JSplitPane {

  public LogDetailPanel(final LogDetailController logDetailController) {
    super(JSplitPane.HORIZONTAL_SPLIT);

    final var requestEditorComponent = logDetailController.getRequestEditor().getComponent();
    final var responseEditorComponent = logDetailController.getResponseEditor().getComponent();

    final var leftPane = new JPanel(new GridBagLayout());
    final var gbcL = new GridBagConstraints();
    gbcL.fill = GridBagConstraints.BOTH;
    gbcL.weightx = 1;
    gbcL.weighty = 1;
    gbcL.insets = new Insets(0, 0, 0, -5); // for margin
    leftPane.add(requestEditorComponent, gbcL);

    final var rightPane = new JPanel(new GridBagLayout());
    final var gbcR = new GridBagConstraints();
    gbcR.fill = GridBagConstraints.BOTH;
    gbcR.weightx = 1;
    gbcR.weighty = 1;
    gbcR.insets = new Insets(0, 0, 0, -15); // for margin
    rightPane.add(responseEditorComponent, gbcR);

    setLeftComponent(leftPane);
    setRightComponent(rightPane);
    setResizeWeight(0.5);
  }
}
