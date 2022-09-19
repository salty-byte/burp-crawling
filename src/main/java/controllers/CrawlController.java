package controllers;

import burp.IBurpExtenderCallbacks;
import com.google.gson.Gson;
import java.io.FileWriter;
import java.io.IOException;
import javax.swing.JFileChooser;
import javax.swing.JOptionPane;
import models.LogEntry;
import models.json.CrawledData;
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

    public void renumber() {
      logTableModel.renumber();
    }

    public void exportCrawledData() {
      final var fileChooser = new JFileChooser();
      int selected = fileChooser.showOpenDialog(logTable);
      if (selected != JFileChooser.APPROVE_OPTION) {
        return;
      }
      final var file = fileChooser.getSelectedFile();
      if (file.exists()) {
        int result = JOptionPane.showConfirmDialog(
            logTable,
            "ファイルが既に存在します。上書きしますか?",
            "警告",
            JOptionPane.OK_CANCEL_OPTION,
            JOptionPane.WARNING_MESSAGE
        );
        if (result != JOptionPane.YES_OPTION) {
          return;
        }
      }

      final var logEntries = logTableModel.getLogEntryAll();
      final var jsonStr = new Gson().toJson(new CrawledData(logEntries));
      try (final var writer = new FileWriter(file)) {
        writer.write(jsonStr);
      } catch (IOException e) {
        JOptionPane.showConfirmDialog(
            logTable,
            "JSON出力時にエラーが発生しました。",
            "エラー",
            JOptionPane.DEFAULT_OPTION,
            JOptionPane.ERROR_MESSAGE
        );
        e.printStackTrace();
        return;
      }

      JOptionPane.showConfirmDialog(
          logTable,
          "JSON出力が完了しました。",
          "完了",
          JOptionPane.DEFAULT_OPTION,
          JOptionPane.INFORMATION_MESSAGE
      );
    }
  }
}
