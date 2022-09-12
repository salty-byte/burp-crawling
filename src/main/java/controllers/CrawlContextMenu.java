package controllers;

import burp.IContextMenuFactory;
import burp.IContextMenuInvocation;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;
import javax.swing.JMenuItem;
import models.LogEntry;

public class CrawlContextMenu implements IContextMenuFactory {

  public static final String ITEM_NAME = "Send to Crawling log";

  private final CrawlController crawlController;
  private final IExtensionHelpers helpers;

  public CrawlContextMenu(final CrawlController crawlController) {
    this.crawlController = crawlController;
    this.helpers = crawlController.getBurpExtenderCallbacks().getHelpers();
  }

  @Override
  public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
    final var crawlMenuItem = new JMenuItem(ITEM_NAME);
    crawlMenuItem.addActionListener(v -> send(invocation.getSelectedMessages()));
    return new ArrayList<>(List.of(crawlMenuItem));
  }

  private void send(final IHttpRequestResponse[] requestResponses) {
    final var logEntries = Arrays.stream(requestResponses)
        .map(this::createLogEntry)
        .collect(Collectors.toList());
    crawlController.getLogTableModel().addLogEntries(logEntries);
  }

  private LogEntry createLogEntry(final IHttpRequestResponse requestResponse) {
    final var requestInfo = helpers.analyzeRequest(
        requestResponse.getHttpService(),
        requestResponse.getRequest()
    );
    final var logEntry = new LogEntry(
        "",
        "",
        requestInfo.getUrl().toString(),
        requestInfo.getMethod(),
        !requestInfo.getParameters().isEmpty(),
        requestResponse.getComment(),
        requestResponse
    );
    logEntry.setRequestResponse(requestResponse);
    return logEntry;
  }
}
