package views.logtable;

import java.awt.datatransfer.DataFlavor;
import java.awt.datatransfer.Transferable;
import java.awt.datatransfer.UnsupportedFlavorException;
import java.util.List;
import java.util.Objects;
import models.LogEntry;

class LogTableTransferable implements Transferable {

  private final DataFlavor dataFlavor;
  private final LogTableModel logTableModel;
  private final int[] transferredIndices;

  LogTableTransferable(final LogTable logTable, final DataFlavor dataFlavor) {
    this.dataFlavor = dataFlavor;
    logTableModel = logTable.getModel();
    transferredIndices = logTable.getSelectedModelIndices();
  }

  @Override
  public DataFlavor[] getTransferDataFlavors() {
    return new DataFlavor[]{dataFlavor};
  }

  @Override
  public boolean isDataFlavorSupported(final DataFlavor flavor) {
    return Objects.equals(dataFlavor, flavor);
  }

  @Override
  public List<LogEntry> getTransferData(final DataFlavor flavor) throws UnsupportedFlavorException {
    if (!isDataFlavorSupported(flavor)) {
      throw new UnsupportedFlavorException(flavor);
    }
    return logTableModel.getLogEntriesAt(transferredIndices);
  }

  public int[] getTransferredRows() {
    return transferredIndices;
  }
}
