package controllers;

import burp.IBurpExtenderCallbacks;
import models.LogEntry;
import views.logtable.LogTable;
import views.logtable.LogTableModel;

public class CrawlController {

  private final IBurpExtenderCallbacks callbacks;
  private final CrawlHelper helper;
  private final LogDetailController logDetailController;
  private final LogTable logTable;
  private final LogTableModel logTableModel;

  public CrawlController(final IBurpExtenderCallbacks callbacks) {
    this.callbacks = callbacks;
    logDetailController = new LogDetailController(callbacks);
    logTableModel = new LogTableModel();
    logTable = new LogTable(logTableModel, logDetailController);
    helper = new CrawlHelper();
  }

  public CrawlHelper getHelper() {
    return helper;
  }

  public IBurpExtenderCallbacks getBurpExtenderCallbacks() {
    return callbacks;
  }

  public LogDetailController getLogDetailController() {
    return logDetailController;
  }

  public LogTable getLogTable() {
    return logTable;
  }

  public LogTableModel getLogTableModel() {
    return logTableModel;
  }

  public class CrawlHelper {

    public void addEmptyLogEntry() {
      final int rowCount = logTableModel.getRowCount();
      final var row = logTable.getSelectedRow();
      final var insertIndex = row == -1 ? rowCount : logTable.convertRowIndexToModel(row) + 1;
      logTable.getModel().addLogEntryAt(new LogEntry(rowCount + 1), insertIndex);
    }
  }
}
