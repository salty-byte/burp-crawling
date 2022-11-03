package views.logtable;

import java.awt.event.MouseEvent;
import javax.swing.table.JTableHeader;

public class LogTableHeader extends JTableHeader {

  final LogTableModel logTableModel;

  LogTableHeader(final LogTable logTable) {
    super(logTable.getColumnModel());
    this.logTableModel = logTable.getModel();
  }

  @Override
  public String getToolTipText(final MouseEvent e) {
    final var p = e.getPoint();
    final var columnIndex = columnModel.getColumnIndexAtX(p.x);
    final var key = logTableModel.getLogEntryKey(columnIndex);
    if (key.getClassification() != Boolean.class) {
      return null;
    }

    final var count = logTableModel.getLogEntryAll().stream()
        .map(entry -> entry.getValueByKey(key))
        .filter(Boolean.class::cast)
        .count();
    return Long.toString(count);
  }
}
