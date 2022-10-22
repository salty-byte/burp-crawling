package exceptions;

public class CrawlException extends Exception {

  private static final long serialVersionUID = 1L;

  public CrawlException(final String message) {
    super(message);
  }
}
