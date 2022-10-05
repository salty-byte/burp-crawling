package models;

import burp.IHttpRequestResponse;
import burp.IRequestInfo;
import burp.IResponseInfo;
import models.json.LogEntryForJson;
import utils.CrawlingUtils;

public class LogEntry {

  private int number;
  private String requestName;
  private String url;
  private String method;
  private short statusCode;
  private String mime;
  private String extension;
  private boolean hasParameter;
  private boolean duplicated;
  private String duplicatedMessage;
  private String remark;
  private TargetType targetType;
  private ColorType colorType;
  private IHttpRequestResponse requestResponse;

  public LogEntry(final int number) {
    this.number = number;
    this.requestName = "";
    this.url = "https://";
    this.method = "GET";
    this.statusCode = (short) 0;
    this.mime = "";
    this.extension = "";
    this.hasParameter = false;
    this.remark = "";
    this.requestResponse = null;
    this.duplicated = false;
    this.duplicatedMessage = "";
    this.targetType = TargetType.NONE;
    this.colorType = ColorType.DEFAULT;
  }

  public LogEntry(final int number, final IHttpRequestResponse requestResponse,
      final IRequestInfo requestInfo, final IResponseInfo responseInfo) {
    this.number = number;
    this.requestName = "";
    this.url = CrawlingUtils.createUrlStringWithQuery(requestInfo.getUrl());
    this.method = requestInfo.getMethod();
    this.statusCode = responseInfo.getStatusCode();
    this.mime = responseInfo.getStatedMimeType();
    this.extension = CrawlingUtils.findExtension(requestInfo.getUrl());
    this.hasParameter = !requestInfo.getParameters().isEmpty();
    this.remark = requestResponse.getComment();
    this.requestResponse = requestResponse;
    this.duplicated = false;
    this.duplicatedMessage = "";
    this.targetType = TargetType.NONE;
    this.colorType = ColorType.DEFAULT;
  }

  public LogEntry(final LogEntryForJson data) {
    this.number = data.getNumber();
    this.requestName = data.getRequestName();
    this.url = data.getUrl();
    this.method = data.getMethod();
    this.statusCode = data.getStatusCode();
    this.mime = data.getMime();
    this.extension = data.getExtension();
    this.hasParameter = data.hasParameter();
    this.remark = data.getRemark();
    this.requestResponse = data.getIHttpRequestResponse();
    this.duplicated = data.isDuplicated();
    this.duplicatedMessage = data.getDuplicatedMessage();
    this.targetType = data.getTargetType();
    this.colorType = data.getColorType();
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
      case STATUS_CODE:
        return getStatusCode();
      case MIME:
        return getMime();
      case EXTENSION:
        return getExtension();
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
        case MIME:
          setMime((String) value);
          break;
        case EXTENSION:
          setExtension((String) value);
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

  public short getStatusCode() {
    return statusCode;
  }

  public void setStatusCode(short statusCode) {
    this.statusCode = statusCode;
  }

  public String getMime() {
    return mime;
  }

  public void setMime(String mime) {
    this.mime = mime;
  }

  public String getExtension() {
    return extension;
  }

  public void setExtension(String extension) {
    this.extension = extension;
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
