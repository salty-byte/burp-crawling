package models;

public enum LogEntryKey {
  NUMBER(String.class, "No.", 30),
  REQUEST_NAME(String.class, "リクエスト名", 300),
  METHOD(String.class, "メソッド", 100),
  URL(String.class, "URL", 300),
  HAS_PARAMETER(Boolean.class, "パラメータ有無", 100),
  REMARK(String.class, "備考", 300),
  ;

  final Class<?> classification;
  final String displayName;
  final int width;

  LogEntryKey(final Class<?> classification, final String displayName, final int width) {
    this.classification = classification;
    this.displayName = displayName;
    this.width = width;
  }

  public Class<?> getClassification() {
    return classification;
  }

  public String getDisplayName() {
    return displayName;
  }

  public int getWidth() {
    return width;
  }
}
