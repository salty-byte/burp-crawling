package controllers;

import burp.IExtensionHelpers;
import com.google.gson.Gson;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.util.List;
import javax.swing.JFileChooser;
import javax.swing.JOptionPane;
import models.ColorType;
import models.LogEntry;
import models.json.CrawledData;
import utils.CrawlingUtils;
import utils.DialogUtils;
import views.logtable.LogTable;
import views.logtable.LogTableModel;

public class CrawlHelper {

  private final IExtensionHelpers extensionHelper;
  private final LogTable logTable;
  private final LogTableModel logTableModel;

  public CrawlHelper(final LogTable logTable) {
    this(null, logTable);
  }

  public CrawlHelper(final IExtensionHelpers extensionHelper, final LogTable logTable) {
    this.extensionHelper = extensionHelper;
    this.logTable = logTable;
    logTableModel = logTable.getModel();
  }

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
    CrawlingUtils.applyDuplicatedRequest(logEntries, extensionHelper);
    logTableModel.updateAllRows();
  }

  public void setLogEntriesColor(final ColorType colorType, final List<LogEntry> logEntries) {
    logEntries.forEach(e -> e.setColorType(colorType));
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
    importCrawledData(file);
  }

  public void importCrawledData(final File file) {
    importCrawledDataAt(file, logTable.getRowCount());
  }

  public void importCrawledDataAt(final File file, final int index) {
    if (!file.exists()) {
      DialogUtils.showError("ファイルが存在しません。", "エラー");
    }

    try (final var reader = new FileReader(file)) {
      final var crawledData = new Gson().fromJson(reader, CrawledData.class);
      logTableModel.addLogEntriesAt(crawledData.toLogEntries(), index);
    } catch (IOException e) {
      DialogUtils.showError("JSON追加時にエラーが発生しました。", "エラー");
      e.printStackTrace();
    }
  }
}
