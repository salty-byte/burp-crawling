package models;

import burp.IHttpRequestResponse;

public class LogEntry {

  private int number;
  private String requestName;
  private String url;
  private String method;
  private boolean hasParameter;
  private boolean duplicated;
  private String duplicatedMessage;
  private String remark;
  private TargetType targetType;
  private ColorType colorType;
  private IHttpRequestResponse requestResponse;

  public LogEntry(final int number) {
    this(number, "", "https://", "GET", false, "", null, false, "", TargetType.NONE,
        ColorType.DEFAULT);
  }

  public LogEntry(final int number, final String requestName, final String url,
      final String method, final boolean hasParameter, final String remark,
      final IHttpRequestResponse requestResponse, final boolean duplicated,
      final String duplicatedMessage, final TargetType targetType, final ColorType colorType) {
    this.number = number;
    this.requestName = requestName;
    this.url = url;
    this.method = method;
    this.hasParameter = hasParameter;
    this.remark = remark;
    this.requestResponse = requestResponse;
    this.duplicated = duplicated;
    this.duplicatedMessage = duplicatedMessage;
    this.targetType = targetType;
    this.colorType = colorType;
  }

  public Object getValueByKey(final LogEntryKey key) {
    switch (key) {
      case NUMBER:
        return getNumber();
      case REQUEST_NAME:
        return getRequestName();
      case URL:
        return getUrl();
      case METHOD:
        return getMethod();
      case HAS_PARAMETER:
        return hasParameter();
      case IS_DUPLICATED:
        return isDuplicated();
      case DUPLICATED_MESSAGE:
        return getDuplicatedMessage();
      case TARGET_AUTO:
        return targetType.hasAuto();
      case TARGET_MANUAL:
        return targetType.hasManual();
      case REMARK:
        return getRemark();
      default:
        return "";
    }
  }

  public void setValueByKey(final LogEntryKey key, final Object value) {
    try {
      switch (key) {
        case NUMBER:
          setNumber((Integer) value);
          break;
        case REQUEST_NAME:
          setRequestName((String) value);
          break;
        case URL:
          setUrl((String) value);
          break;
        case METHOD:
          setMethod((String) value);
          break;
        case HAS_PARAMETER:
          setHasParameter((Boolean) value);
          break;
        case IS_DUPLICATED:
          setDuplicated((Boolean) value);
          break;
        case DUPLICATED_MESSAGE:
          setDuplicatedMessage((String) value);
          break;
        case TARGET_AUTO:
          setAutoTarget((Boolean) value);
          break;
        case TARGET_MANUAL:
          setManualTarget((Boolean) value);
          break;
        case REMARK:
          setRemark((String) value);
          break;
        default:
      }
    } catch (Exception ignored) {
      // do nothing
    }
  }

  public int getNumber() {
    return number;
  }

  public void setNumber(int number) {
    this.number = number;
  }

  public String getRequestName() {
    return requestName;
  }

  public void setRequestName(String requestName) {
    this.requestName = requestName;
  }

  public String getUrl() {
    return url;
  }

  public void setUrl(String url) {
    this.url = url;
  }

  public String getMethod() {
    return method;
  }

  public void setMethod(String method) {
    this.method = method;
  }

  public boolean hasParameter() {
    return hasParameter;
  }

  public void setHasParameter(boolean hasParameter) {
    this.hasParameter = hasParameter;
  }

  public boolean isDuplicated() {
    return duplicated;
  }

  public void setDuplicated(boolean duplicated) {
    this.duplicated = duplicated;
  }

  public String getDuplicatedMessage() {
    return duplicatedMessage;
  }

  public void setDuplicatedMessage(String duplicatedMessage) {
    this.duplicatedMessage = duplicatedMessage;
  }

  public TargetType getTargetType() {
    return targetType;
  }

  public void setTargetType(TargetType targetType) {
    this.targetType = targetType;
  }

  public ColorType getColorType() {
    return colorType;
  }

  public void setColorType(ColorType colorType) {
    this.colorType = colorType;
  }

  public void setAutoTarget(boolean hasAuto) {
    targetType = targetType.setAuto(hasAuto);
  }

  public void setManualTarget(boolean hasManual) {
    targetType = targetType.setManual(hasManual);
  }

  public String getRemark() {
    return remark;
  }

  public void setRemark(String remark) {
    this.remark = remark;
  }

  public IHttpRequestResponse getRequestResponse() {
    return requestResponse;
  }

  public void setRequestResponse(IHttpRequestResponse requestResponse) {
    this.requestResponse = requestResponse;
  }
}
