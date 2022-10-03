package models;

import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

public enum LogEntryKey {
  NUMBER(Integer.class, "No", 50, false, true),
  REQUEST_NAME(String.class, "リクエスト名", 300, true, true),
  METHOD(String.class, "メソッド", 100, false, true),
  URL(String.class, "URL", 300, true, false),
  HAS_PARAMETER(Boolean.class, "パラメータ有無", 100, false, true),
  STATUS_CODE(Short.class, "ステータス", 60, false, false),
  MIME(String.class, "MIME", 60, false, false),
  EXTENSION(String.class, "拡張子", 60, false, false),
  IS_DUPLICATED(Boolean.class, "重複", 100, false, true),
  DUPLICATED_MESSAGE(String.class, "重複箇所", 100, false, false),
  TARGET_AUTO(Boolean.class, "自動対象", 60, false, true),
  TARGET_MANUAL(Boolean.class, "手動対象", 60, false, true),
  REMARK(String.class, "備考", 300, true, true),
  ;

  private static final Map<Class<?>, Function<String, Object>> CAST_MAP = new HashMap<>();

  static {
    CAST_MAP.put(Boolean.class, Boolean::parseBoolean);
    CAST_MAP.put(Integer.class, Integer::parseInt);
    CAST_MAP.put(Short.class, Short::parseShort);
    CAST_MAP.put(String.class, str -> str);
  }

  private final Class<?> classification;
  private final String displayName;
  private final int width;
  private final boolean hasTooltip;
  private final boolean editable;

  LogEntryKey(final Class<?> classification, final String displayName, final int width,
      final boolean hasTooltip, final boolean editable) {
    this.classification = classification;
    this.displayName = displayName;
    this.width = width;
    this.hasTooltip = hasTooltip;
    this.editable = editable;
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

  public boolean isEditable() {
    return editable;
  }

  public Object parseFromString(final String str) {
    if (CAST_MAP.containsKey(classification)) {
      return CAST_MAP.get(classification).apply(str);
    }
    return str;
  }
}
