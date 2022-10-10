package utils;

import java.awt.Component;
import javax.swing.JOptionPane;

public class DialogUtils {

  private DialogUtils() {
    throw new IllegalStateException("Utility class");
  }

  public static void showInfo(final String message, final String title) {
    showInfo(message, title, null);
  }

  public static void showInfo(final String message, final String title, final Component parent) {
    JOptionPane.showConfirmDialog(
        parent,
        message,
        title,
        JOptionPane.DEFAULT_OPTION,
        JOptionPane.INFORMATION_MESSAGE
    );
  }

  public static void showError(final String message, final String title) {
    showError(message, title, null);
  }

  public static void showError(final String message, final String title, final Component parent) {
    JOptionPane.showConfirmDialog(
        parent,
        message,
        title,
        JOptionPane.DEFAULT_OPTION,
        JOptionPane.ERROR_MESSAGE
    );
  }

  public static int confirm(final String message, final String title) {
    return confirm(message, title, null);
  }

  public static int confirm(final String message, final String title, final Component parent) {
    return JOptionPane.showConfirmDialog(
        parent,
        message,
        title,
        JOptionPane.OK_CANCEL_OPTION,
        JOptionPane.WARNING_MESSAGE
    );
  }
}
