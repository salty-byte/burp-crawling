package controllers;

import burp.IBurpExtenderCallbacks;

public class CrawlController {

  private final IBurpExtenderCallbacks callbacks;
  private final LogDetailController logDetailController;

  public CrawlController(final IBurpExtenderCallbacks callbacks) {
    this.callbacks = callbacks;
    this.logDetailController = new LogDetailController(callbacks);
  }

  public IBurpExtenderCallbacks getBurpExtenderCallbacks() {
    return callbacks;
  }

  public LogDetailController getLogDetailController() {
    return logDetailController;
  }
}
