package views;

import javax.swing.JTable;

public class LogTable extends JTable {

  public static final int DEFAULT_HEIGHT = 600;

  private static final String[] columnNames = {"No", "a", "b", "c"};
  private static final String[][] data = {
      {"1", "", "", ""}
  };

  LogTable() {
    super(data, columnNames);
    this.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);
    this.setRowHeight(20);
  }
}
