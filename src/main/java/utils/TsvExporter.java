package utils;

import burp.IExtensionHelpers;
import burp.IParameter;
import burp.IRequestInfo;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import models.LogEntry;

public class TsvExporter {

  private static final String SEPARATOR_TAB = "\t";
  private static final String SEPARATOR_LINE = "\n";

  private final IExtensionHelpers helper;
  private final Map<Byte, String> parameterMap;

  public TsvExporter(final IExtensionHelpers helper) {
    this.helper = helper;
    this.parameterMap = createParameterMap();
  }

  private Map<Byte, String> createParameterMap() {
    final var map = new HashMap<Byte, String>();
    map.put(IParameter.PARAM_URL, "URL");
    map.put(IParameter.PARAM_COOKIE, "Cookie");
    map.put(IParameter.PARAM_BODY, "Body");
    map.put(IParameter.PARAM_MULTIPART_ATTR, "Body");
    map.put(IParameter.PARAM_XML, "XML");
    map.put(IParameter.PARAM_XML_ATTR, "XML");
    map.put(IParameter.PARAM_JSON, "JSON");
    return map;
  }

  public String exportString(final List<LogEntry> logEntries) {
    final var builder = new StringBuilder();
    for (final var logEntry : logEntries) {

      final var requestResponse = logEntry.getRequestResponse();
      if (requestResponse == null || requestResponse.getRequest().length <= 0) {
        builder.append(createFirstLine(logEntry));
        continue;
      }

      final var requestInfo = helper.analyzeRequest(
          requestResponse.getHttpService(),
          requestResponse.getRequest()
      );
      builder.append(createFirstLine(logEntry.getRequestName(), requestInfo));
      builder.append(headersToString(requestInfo, List.of("Cookie:")));
      builder.append(parametersToString(requestInfo));
    }
    return builder.toString();
  }

  public String exportStringOnlyParameters(final List<LogEntry> logEntries) {
    final var builder = new StringBuilder();
    for (final var logEntry : logEntries) {

      final var requestResponse = logEntry.getRequestResponse();
      if (requestResponse == null || requestResponse.getRequest().length <= 0) {
        builder.append(createFirstLine(logEntry));
        continue;
      }

      final var requestInfo = helper.analyzeRequest(
          requestResponse.getHttpService(),
          requestResponse.getRequest()
      );
      builder.append(createFirstLine(logEntry.getRequestName(), requestInfo));
      builder.append(parametersToString(requestInfo, List.of(IParameter.PARAM_COOKIE)));
    }
    return builder.toString();
  }

  private String createFirstLine(final LogEntry logEntry) {
    final var requestName = logEntry.getRequestName();
    final var method = logEntry.getMethod();
    final var urlStr = logEntry.getUrl();
    final var item = new TsvItem(requestName, method, urlStr, "-", "-", "-");
    return itemsToString(List.of(item));
  }

  private String createFirstLine(final String requestName,
      final IRequestInfo requestInfo) {
    final var url = requestInfo.getUrl();
    final var method = requestInfo.getMethod();
    final var urlStr = CrawlingUtils.createUrlStringWithQuery(url);
    final var item = new TsvItem(requestName, method, urlStr, "-", "-", "-");
    return itemsToString(List.of(item));
  }

  private String headersToString(final IRequestInfo requestInfo, List<String> ignoreHeaders) {
    final var items = new LinkedList<TsvItem>();
    final var paths = requestInfo.getUrl().getPath().split("/");
    for (int i = 1; i < paths.length; i++) {
      items.add(new TsvItem("Path", Integer.toString(i), paths[i]));
    }

    final var headers = requestInfo.getHeaders();
    final var headersExcludeFirstLine = headers.subList(1, headers.size());
    final var headerItems = headersExcludeFirstLine.stream()
        .filter(h -> ignoreHeaders.stream().noneMatch(h::startsWith))
        .map(h -> h.split(": ", 2))
        .map(h -> h.length == 2
            ? new TsvItem("Header", h[0], h[1])
            : new TsvItem("Header", h[0], ""))
        .collect(Collectors.toList());
    items.addAll(headerItems);

    return itemsToString(items);
  }

  private String parametersToString(final IRequestInfo requestInfo) {
    return parametersToString(requestInfo, new ArrayList<>());
  }

  private String parametersToString(final IRequestInfo requestInfo, List<Byte> ignoreParameters) {
    final var parameters = requestInfo.getParameters();
    final var items = parameters.stream()
        .filter(h -> !ignoreParameters.contains(h.getType()))
        .map(TsvItem::new)
        .collect(Collectors.toList());
    return itemsToString(items);
  }

  private String escape(final String str) {
    final var escapedStr = str.replaceAll("\\p{Cntrl}", "")
        .replace("\"", "\"\"");
    return String.format("\"%s\"", escapedStr);
  }

  private String itemsToString(final List<TsvItem> items) {
    final var builder = new StringBuilder();
    for (final var item : items) {
      builder.append(escape(item.getRequestName()));
      builder.append(SEPARATOR_TAB);
      builder.append(escape(item.getMethod()));
      builder.append(SEPARATOR_TAB);
      builder.append(escape(item.getUrl()));
      builder.append(SEPARATOR_TAB);
      builder.append(escape(item.getType()));
      builder.append(SEPARATOR_TAB);
      builder.append(escape(item.getName()));
      builder.append(SEPARATOR_TAB);
      builder.append(escape(item.getValue()));
      builder.append(SEPARATOR_LINE);
    }
    return builder.toString();
  }

  private class TsvItem {

    private final String requestName;
    private final String method;
    private final String url;
    private final String type;
    private final String name;
    private final String value;

    public TsvItem(final IParameter parameter) {
      this(
          "",
          "",
          "",
          parameterMap.get(parameter.getType()),
          parameter.getName(),
          parameter.getValue()
      );
    }

    public TsvItem(final String type, final String name, final String value) {
      this("", "", "", type, name, value);
    }

    public TsvItem(final String requestName, final String method, final String url,
        final String type, final String name, final String value) {
      this.requestName = requestName;
      this.method = method;
      this.url = url;
      this.type = type;
      this.name = name;
      this.value = value;
    }

    public String getRequestName() {
      return requestName;
    }

    public String getMethod() {
      return method;
    }

    public String getUrl() {
      return url;
    }

    public String getType() {
      return type;
    }

    public String getName() {
      return name;
    }

    public String getValue() {
      return value;
    }
  }
}
