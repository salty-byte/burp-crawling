package views;

import burp.ITab;
import java.awt.Component;
import java.awt.Panel;

/**
 * MainTab
 */
public class MainTab implements ITab {

  public static final String TAB_NAME = "Crawling";

  public Component createComponent() {
    return new Panel();
  }

  @Override
  public String getTabCaption() {
    return TAB_NAME;
  }

  @Override
  public Component getUiComponent() {
    return createComponent();
  }
}
