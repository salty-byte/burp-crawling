package views;

import javax.swing.SortOrder;
import javax.swing.table.TableModel;
import javax.swing.table.TableRowSorter;

public class LogTableRowSorter<M extends TableModel> extends TableRowSorter<M> {

  public LogTableRowSorter(final M model) {
    super(model);
  }

  @Override
  public void toggleSortOrder(final int columnIndex) {
    if (columnIndex < 0
        || getModelWrapper().getColumnCount() <= columnIndex
        || !isSortable(columnIndex)
    ) {
      return;
    }

    final var keys = getSortKeys();
    if (!keys.isEmpty()) {
      final var sortKey = keys.get(0);
      if (sortKey.getColumn() == columnIndex && sortKey.getSortOrder() == SortOrder.DESCENDING) {
        setSortKeys(null);
        return;
      }
    }

    super.toggleSortOrder(columnIndex);
  }
}
