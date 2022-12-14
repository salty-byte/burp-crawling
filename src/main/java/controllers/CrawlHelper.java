package controllers;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IResponseInfo;
import exceptions.CrawlException;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;
import javax.swing.JFileChooser;
import javax.swing.JOptionPane;
import javax.swing.filechooser.FileNameExtensionFilter;
import models.ColorType;
import models.LogEntry;
import models.json.CrawledData;
import utils.CrawlingUtils;
import utils.DialogUtils;
import utils.JsonUtils;
import utils.OpenApiImporter;
import utils.TsvExporter;
import views.logtable.LogTable;
import views.logtable.LogTableModel;

public class CrawlHelper {

  private final IBurpExtenderCallbacks burpCallbacks;
  private final IExtensionHelpers extensionHelper;
  private final LogTable logTable;
  private final LogTableModel logTableModel;
  private List<LogEntry> markedLogEntries;

  public CrawlHelper(final LogTable logTable) {
    this(null, logTable);
  }

  public CrawlHelper(final IBurpExtenderCallbacks burpCallbacks, final LogTable logTable) {
    this.burpCallbacks = burpCallbacks;
    this.logTable = logTable;
    extensionHelper = burpCallbacks == null ? null : burpCallbacks.getHelpers();
    logTableModel = logTable.getModel();
    markedLogEntries = new ArrayList<>();
  }

  private LogEntry createLogEntry(final IHttpRequestResponse requestResponse) {
    final var requestInfo = extensionHelper.analyzeRequest(
        requestResponse.getHttpService(),
        requestResponse.getRequest()
    );
    final var responseInfo = analyzeResponse(requestResponse.getResponse());
    return new LogEntry(0, requestResponse, requestInfo, responseInfo);
  }

  public IResponseInfo analyzeResponse(final byte[] response) {
    return extensionHelper.analyzeResponse(response == null ? new byte[0] : response);
  }

  public void addEmptyLogEntry() {
    final var rowCount = logTableModel.getRowCount();
    final var row = logTable.getSelectedRow();
    final var insertIndex = row == -1 ? rowCount : logTable.convertRowIndexToModel(row) + 1;
    logTableModel.addLogEntryAt(new LogEntry(rowCount + 1), insertIndex);
  }

  public void addLogEntry(final String requestName, final IHttpRequestResponse requestResponse) {
    final var logEntry = createLogEntry(requestResponse);
    logEntry.setRequestName(requestName);
    logEntry.setNumber(logTableModel.getRowCount() + 1);
    logTableModel.addLogEntry(logEntry);
  }

  public void addLogEntryToSelection(final String requestName,
      final IHttpRequestResponse requestResponse) {
    final var rowCount = logTableModel.getRowCount();
    final var row = logTable.getSelectedRow();
    final var logEntry = createLogEntry(requestResponse);
    logEntry.setRequestName(requestName);
    logEntry.setNumber(rowCount + 1);
    if (row == -1) {
      logTableModel.addLogEntryAt(logEntry, rowCount);
    } else {
      final var insertIndex = logTable.convertRowIndexToModel(row) + 1;
      logTableModel.addLogEntryAt(logEntry, insertIndex);
      logTable.setRowSelection(logEntry);
    }
  }

  public void addLogEntries(final IHttpRequestResponse[] requestResponses) {
    final var logEntries = Arrays.stream(requestResponses)
        .map(this::createLogEntry)
        .collect(Collectors.toList());
    int count = logTableModel.getRowCount();
    for (final var logEntry : logEntries) {
      logEntry.setNumber(++count);
    }
    logTableModel.addLogEntries(logEntries);
  }

  public void removeLogEntries() {
    final var indices = logTable.getSelectedModelIndices();
    logTableModel.removeLogEntriesAt(indices);
  }

  public void removeLogEntries(final List<LogEntry> logEntries) {
    logTableModel.removeLogEntries(logEntries);
  }

  public boolean hasMarkedLogEntries() {
    return !markedLogEntries.isEmpty();
  }

  public void updateMarkedLogEntries() {
    markedLogEntries = logTableModel.getLogEntryAll()
        .stream()
        .filter(markedLogEntries::contains)
        .collect(Collectors.toList());
  }

  public void markLogEntries(final List<LogEntry> logEntries) {
    markedLogEntries = logEntries;
  }

  public void moveMarkedLogEntriesAt(final int index) {
    updateMarkedLogEntries();
    if (!hasMarkedLogEntries()) {
      return;
    }

    final var logEntries = logTableModel.getLogEntryAll();
    final var offset = (int) markedLogEntries.stream()
        .map(logEntries::indexOf)
        .filter(i -> i < index)
        .count();
    final var insertIndex = Math.max(index - offset, 0);
    removeLogEntries(markedLogEntries);
    logTableModel.addLogEntriesAt(markedLogEntries, insertIndex);
    markedLogEntries.clear();
  }

  public void renumber() {
    logTableModel.renumber();
  }

  public void applyRequestNameHash() {
    final var logEntries = logTableModel.getLogEntryAll();
    CrawlingUtils.applyRequestNameHash(logEntries);
    logTableModel.updateAllRows();
  }

  public void applySimilarOrDuplicatedRequest() {
    final var logEntries = logTableModel.getLogEntryAll();
    CrawlingUtils.applySimilarOrDuplicatedRequest(logEntries, extensionHelper);
    logTableModel.updateAllRows();
  }

  public int countRequest(final List<LogEntry> logEntries) {
    return (int) logEntries.stream()
        .filter(LogEntry::hasRequest)
        .count();
  }

  public void sendToRepeater(final List<LogEntry> logEntries) {
    logEntries.stream()
        .filter(LogEntry::hasRequest)
        .forEachOrdered(e -> {
          final var requestResponse = e.getRequestResponse();
          final var request = requestResponse.getRequest();
          final var service = e.getRequestResponse().getHttpService();
          final var host = service.getHost();
          final var port = service.getPort();
          final var useHttps = Objects.equals("https", service.getProtocol());
          final var tabCaption = "No" + e.getNumber();
          burpCallbacks.sendToRepeater(host, port, useHttps, request, tabCaption);
        });
  }

  public void setLogEntriesColor(final ColorType colorType, final List<LogEntry> logEntries) {
    logEntries.forEach(e -> e.setColorType(colorType));
    logTableModel.updateAllRows();
  }

  public void exportToClipboardWithTsv(final List<LogEntry> logEntries) {
    final var data = new TsvExporter(extensionHelper).exportString(logEntries);
    CrawlingUtils.exportToClipBoard(data);
  }

  public void exportParametersToClipboardWithTsv(final List<LogEntry> logEntries) {
    final var data = new TsvExporter(extensionHelper).exportStringOnlyParameters(logEntries);
    CrawlingUtils.exportToClipBoard(data);
  }

  public void exportCrawledData() {
    final var fileChooser = new JFileChooser();
    final var crawlingFilter = new FileNameExtensionFilter("Crawling???????????? (*.json)", "json");
    fileChooser.addChoosableFileFilter(crawlingFilter);
    fileChooser.setFileFilter(crawlingFilter);
    int selected = fileChooser.showSaveDialog(null);
    if (selected != JFileChooser.APPROVE_OPTION) {
      return;
    }

    final var tmpFile = fileChooser.getSelectedFile();
    final var file = crawlingFilter.accept(tmpFile)
        ? tmpFile
        : new File(tmpFile.getAbsolutePath() + "." + crawlingFilter.getExtensions()[0]);
    if (file.exists()) {
      int result = DialogUtils.confirm("?????????????????????????????????????????????????????????????", "??????", logTable.getRootPane());
      if (result != JOptionPane.YES_OPTION) {
        return;
      }
    }

    final var logEntries = logTableModel.getLogEntryAll();
    final var jsonStr = JsonUtils.toJson(new CrawledData(logEntries), CrawledData.class);
    try (final var writer = new FileWriter(file)) {
      writer.write(jsonStr);
    } catch (Exception e) {
      DialogUtils.showError("JSON?????????????????????????????????????????????", "?????????", logTable.getRootPane());
      e.printStackTrace();
      return;
    }

    DialogUtils.showInfo("JSON??????????????????????????????", "??????", logTable.getRootPane());
  }

  public void importCrawledData() {
    final var fileChooser = new JFileChooser();
    final var crawlingFilter = new FileNameExtensionFilter("Crawling???????????? (*.json)", "json");
    final var openApiFilter = new FileNameExtensionFilter("OpenAPI???????????? (*.json;*.yml;*.yaml)",
        "json", "yml", "yaml");
    fileChooser.addChoosableFileFilter(crawlingFilter);
    fileChooser.addChoosableFileFilter(openApiFilter);
    fileChooser.setFileFilter(crawlingFilter);
    int selected = fileChooser.showOpenDialog(null);
    if (selected != JFileChooser.APPROVE_OPTION) {
      return;
    }
    final var file = fileChooser.getSelectedFile();
    importCrawledData(file);
  }

  public void importCrawledData(final File file) {
    importCrawledDataAt(file, logTable.getRowCount());
  }

  public void importCrawledDataAt(final File file, final int index) {
    if (!file.exists()) {
      DialogUtils.showError("????????????????????????????????????", "?????????", logTable.getRootPane());
    }

    try {
      final var logEntries = loadFile(file);
      logTableModel.addLogEntriesAt(logEntries, index);
    } catch (Exception e) {
      DialogUtils.showError("JSON?????????????????????????????????????????????", "?????????", logTable.getRootPane());
      e.printStackTrace();
    }
  }

  private List<LogEntry> loadFile(final File file) throws IOException, CrawlException {
    if (OpenApiImporter.isOpenApi(file)) {
      return OpenApiImporter.parse(file);
    }

    final var crawledData = JsonUtils.fromJson(file, CrawledData.class);
    return crawledData.toLogEntries();
  }
}
