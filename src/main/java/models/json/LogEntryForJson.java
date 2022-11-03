package models.json;

import burp.IHttpRequestResponse;
import models.ColorType;
import models.LogEntry;
import models.TargetType;

public class LogEntryForJson {

  private final int number;
  private final String pageTitle;
  private final String requestName;
  private final String url;
  private final String method;
  private final short statusCode;
  private final String mime;
  private final String extension;
  private final boolean hasParameter;
  private final boolean duplicated;
  private final boolean similar;
  private final String checkedMessage;
  private final byte targetType;
  private final byte colorType;
  private final String remark;
  private final String date;
  private final RequestResponse requestResponse;

  public LogEntryForJson(final LogEntry entry) {
    this.number = entry.getNumber();
    this.pageTitle = entry.getPageTitle();
    this.requestName = entry.getRequestName();
    this.url = entry.getUrl();
    this.method = entry.getMethod();
    this.statusCode = entry.getStatusCode();
    this.mime = entry.getMime();
    this.extension = entry.getExtension();
    this.hasParameter = entry.hasParameter();
    this.duplicated = entry.isDuplicated();
    this.similar = entry.isSimilar();
    this.checkedMessage = entry.getCheckedMessage();
    this.targetType = entry.getTargetType().getValue();
    this.colorType = entry.getColorType().getValue();
    this.date = entry.getDate();
    this.remark = entry.getRemark();
    final var iReqRes = entry.getRequestResponse();
    requestResponse = iReqRes == null ? null : new RequestResponse(iReqRes);
  }

  public int getNumber() {
    return number;
  }

  public String getPageTitle() {
    return pageTitle;
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

  public short getStatusCode() {
    return statusCode;
  }

  public String getMime() {
    return mime;
  }

  public String getExtension() {
    return extension;
  }

  public boolean hasParameter() {
    return hasParameter;
  }

  public boolean isDuplicated() {
    return duplicated;
  }

  public boolean isSimilar() {
    return similar;
  }

  public String getCheckedMessage() {
    return checkedMessage;
  }

  public TargetType getTargetType() {
    return TargetType.fromByte(targetType);
  }

  public ColorType getColorType() {
    return ColorType.fromByte(colorType);
  }

  public String getDate() {
    return date;
  }

  public String getRemark() {
    return remark;
  }

  public RequestResponse getRequestResponse() {
    return requestResponse;
  }

  public IHttpRequestResponse getIHttpRequestResponse() {
    return requestResponse == null ? null : requestResponse.toIHttpRequestResponse();
  }
}
