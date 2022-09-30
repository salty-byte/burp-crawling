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
import models.ColorType;
import models.LogEntry;
import models.TargetType;
import views.logtable.LogTableModel;

public class CrawlContextMenu implements IContextMenuFactory {

  public static final String ITEM_NAME = "Send to Crawling log";

  private final LogTableModel logTableModel;
  private final IExtensionHelpers helpers;

  public CrawlContextMenu(final CrawlController crawlController) {
    this.logTableModel = crawlController.getLogTableModel();
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
    int count = logTableModel.getRowCount();
    for (final var logEntry : logEntries) {
      logEntry.setNumber(++count);
    }
    logTableModel.addLogEntries(logEntries);
  }

  private LogEntry createLogEntry(final IHttpRequestResponse requestResponse) {
    final var requestInfo = helpers.analyzeRequest(
        requestResponse.getHttpService(),
        requestResponse.getRequest()
    );
    final var logEntry = new LogEntry(
        0,
        "",
        requestInfo.getUrl().toString(),
        requestInfo.getMethod(),
        !requestInfo.getParameters().isEmpty(),
        requestResponse.getComment(),
        requestResponse,
        false,
        "",
        TargetType.NONE,
        ColorType.DEFAULT
    );
    logEntry.setRequestResponse(requestResponse);
    return logEntry;
  }
}
