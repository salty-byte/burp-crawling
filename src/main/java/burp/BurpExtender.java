package burp;

import controllers.CrawlContextMenu;
import controllers.CrawlController;
import views.MainTab;

/**
 * burp-crawling: for BurpSuite Extension
 */
public class BurpExtender implements IBurpExtender {

  public static final String EXTENSION_NAME = "Crawling";

  @Override
  public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
    callbacks.setExtensionName(EXTENSION_NAME);

    final var crawlController = new CrawlController(callbacks);
    callbacks.addSuiteTab(new MainTab(crawlController));
    callbacks.registerContextMenuFactory(new CrawlContextMenu(crawlController));
  }
}
