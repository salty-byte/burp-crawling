package controllers;

import burp.IBurpExtenderCallbacks;
import com.google.gson.Gson;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.util.List;
import javax.swing.JFileChooser;
import javax.swing.JOptionPane;
import models.LogEntry;
import models.json.CrawledData;
import utils.CrawlingUtils;
import utils.DialogUtils;
import views.logtable.LogTable;
import views.logtable.LogTableModel;
import views.logtable.LogTableMouseListener;

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

    // later settings
    logTable.addMouseListener(new LogTableMouseListener(helper, logTable));
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
      final var rowCount = logTableModel.getRowCount();
      final var row = logTable.getSelectedRow();
      final var insertIndex = row == -1 ? rowCount : logTable.convertRowIndexToModel(row) + 1;
      logTableModel.addLogEntryAt(new LogEntry(rowCount + 1), insertIndex);
    }

    public void removeLogEntries() {
      final var indices = logTable.getSelectedModelIndices();
      logTableModel.removeLogEntriesAt(indices);
    }

    public void removeLogEntries(final List<LogEntry> logEntries) {
      logTableModel.removeLogEntries(logEntries);
    }

    public void renumber() {
      logTableModel.renumber();
    }

    public void applyRequestNameHash() {
      final var logEntries = logTableModel.getLogEntryAll();
      CrawlingUtils.applyRequestNameHash(logEntries);
      logTableModel.updateAllRows();
    }

    public void applyDuplicatedRequest() {
      final var logEntries = logTableModel.getLogEntryAll();
      CrawlingUtils.applyDuplicatedRequest(logEntries, callbacks.getHelpers());
      logTableModel.updateAllRows();
    }

    public void exportCrawledData() {
      final var fileChooser = new JFileChooser();
      int selected = fileChooser.showOpenDialog(null);
      if (selected != JFileChooser.APPROVE_OPTION) {
        return;
      }
      final var file = fileChooser.getSelectedFile();
      if (file.exists()) {
        int result = DialogUtils.confirm("ファイルが既に存在します。上書きしますか?", "警告");
        if (result != JOptionPane.YES_OPTION) {
          return;
        }
      }

      final var logEntries = logTableModel.getLogEntryAll();
      final var jsonStr = new Gson().toJson(new CrawledData(logEntries));
      try (final var writer = new FileWriter(file)) {
        writer.write(jsonStr);
      } catch (IOException e) {
        DialogUtils.showError("JSON出力時にエラーが発生しました。", "エラー");
        e.printStackTrace();
        return;
      }

      DialogUtils.showInfo("JSON出力が完了しました。", "完了");
    }

    public void importCrawledData() {
      final var fileChooser = new JFileChooser();
      int selected = fileChooser.showOpenDialog(null);
      if (selected != JFileChooser.APPROVE_OPTION) {
        return;
      }
      final var file = fileChooser.getSelectedFile();
      if (!file.exists()) {
        DialogUtils.showError("ファイルが存在しません。", "エラー");
      }

      try (final var reader = new FileReader(file)) {
        final var crawledData = new Gson().fromJson(reader, CrawledData.class);
        logTableModel.addLogEntries(crawledData.toLogEntries());
      } catch (IOException e) {
        DialogUtils.showError("JSON追加時にエラーが発生しました。", "エラー");
        e.printStackTrace();
        return;
      }

      DialogUtils.showInfo("JSON追加が完了しました。", "完了");
    }
  }
}
