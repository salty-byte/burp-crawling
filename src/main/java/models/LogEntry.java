package models;

import burp.IHttpRequestResponse;

public class LogEntry {

  private String number;
  private String requestName;
  private String url;
  private String method;
  private boolean hasParameter;
  private String remark;
  private IHttpRequestResponse requestResponse;

  public LogEntry() {
    this("1", "", "https://", "GET", false, "", null);
  }

  public LogEntry(final String number, final String requestName, final String url,
      final String method, final boolean hasParameter, final String remark,
      final IHttpRequestResponse requestResponse) {
    this.number = number;
    this.requestName = requestName;
    this.url = url;
    this.method = method;
    this.hasParameter = hasParameter;
    this.remark = remark;
    this.requestResponse = requestResponse;
  }

  public Object getValueByKey(final LogEntryKey key) {
    switch (key) {
      case NUMBER:
        return number;
      case REQUEST_NAME:
        return requestName;
      case URL:
        return url;
      case METHOD:
        return method;
      case HAS_PARAMETER:
        return hasParameter;
      case REMARK:
        return remark;
      default:
        return "";
    }
  }

  public void setValueByKey(final LogEntryKey key, final Object value) {
    try {
      switch (key) {
        case NUMBER:
          setNumber((String) value);
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
        case REMARK:
          setRemark((String) value);
          break;
        default:
      }
    } catch (Exception ignored) {
      // do nothing
    }
  }

  public void setNumber(String number) {
    this.number = number;
  }

  public void setRequestName(String requestName) {
    this.requestName = requestName;
  }

  public void setUrl(String url) {
    this.url = url;
  }

  public void setMethod(String method) {
    this.method = method;
  }

  public void setHasParameter(boolean hasParameter) {
    this.hasParameter = hasParameter;
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
