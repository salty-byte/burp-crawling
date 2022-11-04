package controllers;

import burp.IBurpExtenderCallbacks;
import views.logtable.LogTable;
import views.logtable.LogTableModel;
import views.logtable.LogTableMouseListener;

public class CrawlController {

  private final IBurpExtenderCallbacks callbacks;
  private final CrawlHelper helper;
  private final CrawlProxyController proxyController;
  private final LogDetailController logDetailController;
  private final LogTable logTable;
  private final LogTableModel logTableModel;

  public CrawlController(final IBurpExtenderCallbacks callbacks) {
    this.callbacks = callbacks;
    logDetailController = new LogDetailController(callbacks);
    logTableModel = new LogTableModel();
    logTable = new LogTable(logTableModel, logDetailController);
    helper = new CrawlHelper(callbacks, logTable);
    proxyController = new CrawlProxyController(callbacks, helper);

    // later settings
    logTable.addMouseListener(new LogTableMouseListener(helper, logTable));
  }

  public CrawlHelper getHelper() {
    return helper;
  }

  public CrawlProxyController getProxyController() {
    return proxyController;
  }

  public IBurpExtenderCallbacks getBurpExtenderCallbacks() {
    return callbacks;
  }

  public LogDetailController getLogDetailController() {
    return logDetailController;
  }

  public LogTable getLogTable() {
    return logTable;
  }

  public LogTableModel getLogTableModel() {
    return logTableModel;
  }
}
