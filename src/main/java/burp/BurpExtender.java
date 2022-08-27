package burp;

import views.MainTab;

/**
 * burp-crawling: for BurpSuite Extension
 */
public class BurpExtender implements IBurpExtender {

  public static final String EXTENSION_NAME = "Crawling";

  @Override
  public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
    callbacks.setExtensionName(EXTENSION_NAME);
    callbacks.addSuiteTab(new MainTab());
  }
}
