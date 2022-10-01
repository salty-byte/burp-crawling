package controllers;

import burp.IInterceptedProxyMessage;
import burp.IProxyListener;

public class CrawlProxy implements IProxyListener {

  private final CrawlHelper crawlHelper;

  public CrawlProxy(final CrawlHelper crawlHelper) {
    this.crawlHelper = crawlHelper;
  }

  @Override
  public void processProxyMessage(final boolean messageIsRequest,
      final IInterceptedProxyMessage message) {
    if (messageIsRequest) {
      return;
    }

    final var requestResponse = message.getMessageInfo();
    requestResponse.setComment(""); // clear the comment to remove request id
    crawlHelper.addLogEntry(requestResponse);
  }
}
