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
  private IHttpRequestResponse requestResponse;

  public LogEntry(final int number) {
    this(number, "", "https://", "GET", false, "", null, false, "");
  }

  public LogEntry(final int number, final String requestName, final String url,
      final String method, final boolean hasParameter, final String remark,
      final IHttpRequestResponse requestResponse, final boolean duplicated,
      final String duplicatedMessage) {
    this.number = number;
    this.requestName = requestName;
    this.url = url;
    this.method = method;
    this.hasParameter = hasParameter;
    this.remark = remark;
    this.requestResponse = requestResponse;
    this.duplicated = duplicated;
    this.duplicatedMessage = duplicatedMessage;
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
          setNumber((int) value);
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
          setHasParameter((boolean) value);
          break;
        case IS_DUPLICATED:
          setDuplicated((boolean) value);
          break;
        case DUPLICATED_MESSAGE:
          setDuplicatedMessage((String) value);
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
