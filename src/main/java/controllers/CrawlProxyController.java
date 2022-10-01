package controllers;

import burp.IBurpExtenderCallbacks;

public class CrawlProxyController {

  private final IBurpExtenderCallbacks burpCallbacks;
  private final CrawlProxy proxy;

  public CrawlProxyController(final IBurpExtenderCallbacks burpCallbacks,
      final CrawlHelper crawlHelper) {
    this.burpCallbacks = burpCallbacks;
    this.proxy = new CrawlProxy(crawlHelper);
  }

  private boolean hasRegistered() {
    return burpCallbacks.getProxyListeners()
        .stream()
        .anyMatch(l -> l.equals(proxy));
  }

  public void enable() {
    if (hasRegistered()) {
      return;
    }
    burpCallbacks.registerProxyListener(proxy);
  }

  public void disable() {
    burpCallbacks.removeProxyListener(proxy);
  }
}
