package controllers;

import burp.IBurpExtenderCallbacks;
import burp.IHttpRequestResponse;
import burp.IInterceptedProxyMessage;
import burp.IProxyListener;

public class CrawlProxy implements IProxyListener {

  private final IBurpExtenderCallbacks burpCallbacks;
  private final CrawlHelper crawlHelper;
  private boolean onlyInScope;

  public CrawlProxy(final IBurpExtenderCallbacks burpCallbacks, final CrawlHelper crawlHelper) {
    this.burpCallbacks = burpCallbacks;
    this.crawlHelper = crawlHelper;
    this.onlyInScope = false;
  }

  @Override
  public void processProxyMessage(final boolean messageIsRequest,
      final IInterceptedProxyMessage message) {
    if (messageIsRequest) {
      return;
    }

    final var requestResponse = message.getMessageInfo();
    if (!canImportData(requestResponse)) {
      return;
    }

    requestResponse.setComment(""); // clear the comment to remove request id
    crawlHelper.addLogEntry(requestResponse);
  }

  private boolean canImportData(final IHttpRequestResponse requestResponse) {
    if (!onlyInScope) {
      return true;
    }

    final var requestInfo = burpCallbacks.getHelpers().analyzeRequest(
        requestResponse.getHttpService(),
        requestResponse.getRequest()
    );
    return burpCallbacks.isInScope(requestInfo.getUrl());
  }

  public void setOnlyInScope(final boolean onlyInScope) {
    this.onlyInScope = onlyInScope;
  }
}
