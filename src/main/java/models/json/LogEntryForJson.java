package models.json;

import models.LogEntry;

public class LogEntryForJson {

  private final int number;
  private final String requestName;
  private final String url;
  private final String method;
  private final boolean hasParameter;
  private final String remark;
  private final RequestResponse requestResponse;

  public LogEntryForJson(final LogEntry entry) {
    this.number = entry.getNumber();
    this.requestName = entry.getRequestName();
    this.url = entry.getUrl();
    this.method = entry.getMethod();
    this.hasParameter = entry.hasParameter();
    this.remark = entry.getRemark();
    final var iReqRes = entry.getRequestResponse();
    requestResponse = iReqRes == null ? null : new RequestResponse(iReqRes);
  }

  public int getNumber() {
    return number;
  }

  public String getRequestName() {
    return requestName;
  }

  public String getUrl() {
    return url;
  }

  public String getMethod() {
    return method;
  }

  public boolean hasParameter() {
    return hasParameter;
  }

  public String getRemark() {
    return remark;
  }

  public RequestResponse getRequestResponse() {
    return requestResponse;
  }

  public LogEntry toLogEntry() {
    return new LogEntry(
        number,
        requestName,
        url,
        method,
        hasParameter,
        remark,
        requestResponse == null ? null : requestResponse.toIHttpRequestResponse()
    );
  }
}
