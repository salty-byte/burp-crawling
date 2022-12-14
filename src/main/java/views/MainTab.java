package views;

import burp.ITab;
import controllers.CrawlController;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import javax.swing.JComponent;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.border.MatteBorder;
import views.logtable.LogTable;

/**
 * クローリング機能のメインとなるタブ
 */
public class MainTab implements ITab {

  public static final String TAB_NAME = "Crawling";

  private final JComponent component;

  public MainTab(final CrawlController crawlController) {
    final var logPanel = new JScrollPane(crawlController.getLogTable());
    final var logDetailPanel = new LogDetailPanel(crawlController.getLogDetailController());
    final var headerPanel = new HeaderPanel(crawlController.getProxyController());

    final var splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
    splitPane.setTopComponent(logPanel);
    splitPane.setBottomComponent(logDetailPanel);
    splitPane.setDividerLocation(LogTable.DEFAULT_HEIGHT);

    final var leftPane = new JPanel();
    leftPane.setLayout(new BorderLayout());
    leftPane.add(headerPanel, BorderLayout.NORTH);
    leftPane.add(splitPane, BorderLayout.CENTER);

    final var rightPane = new ControlPanel(crawlController);
    rightPane.setBorder(new MatteBorder(0, 2, 0, 0, Color.DARK_GRAY));

    component = new JPanel();
    component.setLayout(new BorderLayout());
    component.add(leftPane, BorderLayout.CENTER);
    component.add(rightPane, BorderLayout.EAST);
  }

  @Override
  public String getTabCaption() {
    return TAB_NAME;
  }

  @Override
  public Component getUiComponent() {
    return component;
  }
}
