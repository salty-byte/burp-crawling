package controllers;

import burp.IBurpExtenderCallbacks;
import burp.IHttpRequestResponse;
import burp.IInterceptedProxyMessage;
import burp.IProxyListener;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import utils.CrawlingUtils;

public class CrawlProxy implements IProxyListener {

  private final IBurpExtenderCallbacks burpCallbacks;
  private final CrawlHelper crawlHelper;
  private boolean onlyInScope;
  private String requestName;
  private boolean usingExcludedMime;
  private boolean usingExcludedExtensions;
  private List<String> excludedMime;
  private List<String> excludedExtensions;

  public CrawlProxy(final IBurpExtenderCallbacks burpCallbacks, final CrawlHelper crawlHelper) {
    this.burpCallbacks = burpCallbacks;
    this.crawlHelper = crawlHelper;
    this.onlyInScope = false;
    this.requestName = "";
    this.usingExcludedMime = false;
    this.usingExcludedExtensions = false;
    this.excludedMime = new ArrayList<>();
    this.excludedExtensions = new ArrayList<>();
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
    crawlHelper.addLogEntry(requestName, requestResponse);
  }

  private boolean canImportData(final IHttpRequestResponse requestResponse) {
    final var requestInfo = burpCallbacks.getHelpers().analyzeRequest(
        requestResponse.getHttpService(),
        requestResponse.getRequest()
    );
    final var responseInfo = crawlHelper.analyzeResponse(requestResponse.getResponse());
    final var url = requestInfo.getUrl();
    final var mime = responseInfo.getStatedMimeType();
    return isInScope(url) && isInMime(mime) && isInExtensions(url);
  }

  private boolean isInScope(final URL url) {
    if (!onlyInScope) {
      return true;
    }
    return burpCallbacks.isInScope(url);
  }

  private boolean isInMime(final String mime) {
    if (!usingExcludedMime) {
      return true;
    }
    return !excludedMime.contains(mime);
  }

  private boolean isInExtensions(final URL url) {
    if (!usingExcludedExtensions) {
      return true;
    }
    final var extension = CrawlingUtils.findExtension(url);
    return !excludedExtensions.contains(extension);
  }

  public void setOnlyInScope(final boolean onlyInScope) {
    this.onlyInScope = onlyInScope;
  }

  public void useExcludedMime(boolean usingExcludedMime) {
    this.usingExcludedMime = usingExcludedMime;
  }

  public void useExcludedExtensions(boolean usingExcludedExtensions) {
    this.usingExcludedExtensions = usingExcludedExtensions;
  }

  public void setRequestName(final String requestName) {
    this.requestName = requestName;
  }

  public void setExcludedMime(List<String> excludedMime) {
    this.excludedMime = excludedMime;
  }

  public void setExcludedExtensions(List<String> excludedExtensions) {
    this.excludedExtensions = excludedExtensions;
  }
}
