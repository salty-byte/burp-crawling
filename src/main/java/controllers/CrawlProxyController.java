package controllers;

import burp.IBurpExtenderCallbacks;
import java.util.List;

public class CrawlProxyController {

  private final IBurpExtenderCallbacks burpCallbacks;
  private final CrawlProxy proxy;

  public CrawlProxyController(final IBurpExtenderCallbacks burpCallbacks,
      final CrawlHelper crawlHelper) {
    this.burpCallbacks = burpCallbacks;
    this.proxy = new CrawlProxy(burpCallbacks, crawlHelper);
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

  public void setOnlyInScope(final boolean targetOnly) {
    proxy.setOnlyInScope(targetOnly);
  }

  public void setAddingToSelection(final boolean addingToSelection) {
    proxy.setAddingToSelection(addingToSelection);
  }

  public void setRequestName(final String requestName) {
    proxy.setRequestName(requestName);
  }

  public void useExcludedMime(boolean usingExcludedMime) {
    proxy.useExcludedMime(usingExcludedMime);
  }

  public void useExcludedExtensions(boolean usingExcludedExtensions) {
    proxy.useExcludedExtensions(usingExcludedExtensions);
  }

  public void setExcludedMime(List<String> excludedMime) {
    proxy.setExcludedMime(excludedMime);
  }

  public void setExcludedExtensions(List<String> excludedExtensions) {
    proxy.setExcludedExtensions(excludedExtensions);
  }
}
