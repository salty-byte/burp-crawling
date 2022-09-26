package views.logtable;

import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.DataFlavor;
import java.awt.datatransfer.StringSelection;
import java.awt.datatransfer.Transferable;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;
import javax.swing.JComponent;
import javax.swing.JTable;
import javax.swing.TransferHandler;
import models.LogEntry;

class LogTableRowTransferHandler extends TransferHandler {

  private final DataFlavor dataFlavor;
  private int insertIndex;

  LogTableRowTransferHandler() {
    super();
    dataFlavor = new DataFlavor(List.class, "List of items");
    insertIndex = -1;
  }

  @Override
  protected Transferable createTransferable(final JComponent c) {
    return new LogTableTransferable((LogTable) c, dataFlavor);
  }

  @Override
  public boolean canImport(final TransferSupport support) {
    return support.isDrop() && support.isDataFlavorSupported(dataFlavor);
  }

  @Override
  public int getSourceActions(final JComponent c) {
    return TransferHandler.MOVE;
  }

  @Override
  public boolean importData(final TransferSupport support) {
    if (!(support.getDropLocation() instanceof JTable.DropLocation)) {
      return false;
    }

    try {
      final var dropLocation = (JTable.DropLocation) support.getDropLocation();
      final var table = (LogTable) support.getComponent();
      final var tableModel = table.getModel();
      final int maxIndex = table.getRowCount();
      final int droppedIndex = dropLocation.getRow();
      insertIndex = droppedIndex < 0 ? maxIndex : Math.min(droppedIndex, maxIndex);

      @SuppressWarnings("unchecked") final var logEntries = (List<LogEntry>) support
          .getTransferable().getTransferData(dataFlavor);
      tableModel.addLogEntriesAt(logEntries, insertIndex);
      table.getSelectionModel()
          .addSelectionInterval(insertIndex, insertIndex + logEntries.size() - 1);
      return true;
    } catch (Exception e) {
      e.printStackTrace();
    }
    return false;
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
