package views.logtable;

import controllers.CrawlHelper;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.DataFlavor;
import java.awt.datatransfer.StringSelection;
import java.awt.datatransfer.Transferable;
import java.awt.datatransfer.UnsupportedFlavorException;
import java.io.File;
import java.io.IOException;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;
import javax.swing.JComponent;
import javax.swing.JTable;
import javax.swing.TransferHandler;
import models.LogEntry;

class LogTableTransferHandler extends TransferHandler {

  private final DataFlavor rowDataFlavor;
  private int insertIndex;

  LogTableTransferHandler() {
    super();
    rowDataFlavor = new DataFlavor(List.class, "List of table rows");
    insertIndex = -1;
  }

  @Override
  protected Transferable createTransferable(final JComponent c) {
    return new LogTableTransferable((LogTable) c, rowDataFlavor);
  }

  @Override
  public boolean canImport(final TransferSupport support) {
    return support.isDrop() && (canImportTableRows(support) || canImportLocalFile(support));
  }

  private boolean canImportString(final TransferSupport support) {
    return support.isDataFlavorSupported(DataFlavor.stringFlavor);
  }

  private boolean canImportTableRows(final TransferSupport support) {
    return support.isDataFlavorSupported(rowDataFlavor);
  }

  private boolean canImportLocalFile(final TransferSupport support) {
    return support.isDataFlavorSupported(DataFlavor.javaFileListFlavor);
  }

  @Override
  public int getSourceActions(final JComponent c) {
    return TransferHandler.MOVE;
  }

  @Override
  public boolean importData(final TransferSupport support) {
    try {
      if (support.isDrop()) {
        return importDataWithDrop(support);
      } else {
        return importDataWithoutDrop(support);
      }
    } catch (IOException | UnsupportedFlavorException e) {
      e.printStackTrace();
    }
    return false;
  }

  private boolean importDataWithoutDrop(final TransferSupport support)
      throws IOException, UnsupportedFlavorException {
    if (canImportString(support)) {
      return pasteToTable(support);
    }
    return false;
  }

  private boolean importDataWithDrop(final TransferSupport support)
      throws IOException, UnsupportedFlavorException {
    if (canImportTableRows(support)) {
      return copyTableRows(support);
    }
    if (canImportLocalFile(support)) {
      return importLocalFile(support);
    }
    return false;
  }

  private boolean pasteToTable(final TransferSupport support)
      throws IOException, UnsupportedFlavorException {
    final var table = (LogTable) support.getComponent();
    final var data = (String) support.getTransferable().getTransferData(DataFlavor.stringFlavor);
    table.pasteToSelectedCells(data);
    return true;
  }

  private boolean copyTableRows(final TransferSupport support)
      throws IOException, UnsupportedFlavorException {
    final var dropLocation = (JTable.DropLocation) support.getDropLocation();
    final var table = (LogTable) support.getComponent();
    insertIndex = table.calcInsertIndex(dropLocation.getRow());

    @SuppressWarnings("unchecked") final var logEntries = (List<LogEntry>) support.getTransferable()
        .getTransferData(rowDataFlavor);
    table.getModel().addLogEntriesAt(logEntries, insertIndex);
    table.getSelectionModel()
        .addSelectionInterval(insertIndex, insertIndex + logEntries.size() - 1);
    return true;
  }

  private boolean importLocalFile(final TransferSupport support)
      throws IOException, UnsupportedFlavorException {
    final var dropLocation = (JTable.DropLocation) support.getDropLocation();
    final var table = (LogTable) support.getComponent();
    insertIndex = table.calcInsertIndex(dropLocation.getRow());

    @SuppressWarnings("unchecked") final var files = (List<File>) support.getTransferable()
        .getTransferData(DataFlavor.javaFileListFlavor);
    final var crawlHelper = new CrawlHelper(table);
    files.stream()
        .sorted(Comparator.reverseOrder())
        .forEach(f -> crawlHelper.importCrawledDataAt(f, insertIndex));
    return true;
  }

  @Override
  public void exportToClipboard(JComponent c, Clipboard clipboard, int action)
      throws IllegalStateException {
    if (!(c instanceof LogTable)) {
      super.exportToClipboard(c, clipboard, action);
      return;
    }

    final var logTable = (LogTable) c;
    final var ss = new StringSelection(logTable.selectionsToString());
    clipboard.setContents(ss, ss);
  }

  @Override
  protected void exportDone(final JComponent c, final Transferable transferable, final int action) {
    if (action != TransferHandler.MOVE || insertIndex < 0) {
      return;
    }
    if (!(transferable instanceof LogTableTransferable)) {
      return;
    }

    final var table = (LogTable) c;
    final var tableModel = table.getModel();
    final var indices = ((LogTableTransferable) transferable).getTransferredRows();
    final var insertedCount = indices.length;
    Arrays.stream(indices)
        .map(i -> (i < insertIndex) ? i : i + insertedCount)
        .boxed() // to reverse order
        .sorted(Comparator.reverseOrder())
        .forEachOrdered(tableModel::removeLogEntryAt);
    insertIndex = -1;
  }
}
