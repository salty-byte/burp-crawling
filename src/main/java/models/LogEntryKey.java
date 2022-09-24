package models;

public enum LogEntryKey {
  NUMBER(Integer.class, "No", 50, false),
  REQUEST_NAME(String.class, "リクエスト名", 300, true),
  METHOD(String.class, "メソッド", 100, false),
  URL(String.class, "URL", 300, true),
  HAS_PARAMETER(Boolean.class, "パラメータ有無", 100, false),
  IS_DUPLICATED(Boolean.class, "重複", 100, false),
  DUPLICATED_MESSAGE(String.class, "重複箇所", 100, false),
  TARGET_AUTO(Boolean.class, "自動対象", 60, false),
  TARGET_MANUAL(Boolean.class, "手動対象", 60, false),
  REMARK(String.class, "備考", 300, true),
  ;

  final Class<?> classification;
  final String displayName;
  final int width;
  final boolean hasTooltip;

  LogEntryKey(final Class<?> classification, final String displayName, final int width,
      final boolean hasTooltip) {
    this.classification = classification;
    this.displayName = displayName;
    this.width = width;
    this.hasTooltip = hasTooltip;
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

  public boolean hasTooltip() {
    return hasTooltip;
  }
}
