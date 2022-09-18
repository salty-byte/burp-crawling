package controllers;

import burp.IBurpExtenderCallbacks;
import views.logtable.LogTableModel;

public class CrawlController {

  private final IBurpExtenderCallbacks callbacks;
  private final LogDetailController logDetailController;
  private final LogTableModel logTableModel;

  public CrawlController(final IBurpExtenderCallbacks callbacks) {
    this.callbacks = callbacks;
    logDetailController = new LogDetailController(callbacks);
    logTableModel = new LogTableModel();
  }

  public IBurpExtenderCallbacks getBurpExtenderCallbacks() {
    return callbacks;
  }

  public LogDetailController getLogDetailController() {
    return logDetailController;
  }

  public LogTableModel getLogTableModel() {
    return logTableModel;
  }
}
