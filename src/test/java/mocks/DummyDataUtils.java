package mocks;

import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.IParameter;
import burp.IRequestInfo;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.List;
import models.LogEntry;

public class DummyDataUtils {

  public static IHttpService createIHttpService() {
    return createIHttpService("example.com", 443, "https");
  }

  public static IHttpService createEmptyIHttpService() {
    return createIHttpService(null, 0, null);
  }

  static IHttpService createIHttpService(final String host, final int port, final String protocol) {
    return new IHttpService() {
      @Override
      public String getHost() {
        return host;
      }

      @Override
      public int getPort() {
        return port;
      }

      @Override
      public String getProtocol() {
        return protocol;
      }
    };
  }

  public static IHttpRequestResponse createIHttpRequestResponse() {
    final var request = "request".getBytes(StandardCharsets.UTF_8);
    final var response = "response".getBytes(StandardCharsets.UTF_8);
    return createIHttpRequestResponse(request, response, createIHttpService());
  }

  public static IHttpRequestResponse createEmptyIHttpRequestResponse() {
    return createIHttpRequestResponse(null, null, null);
  }

  public static IHttpRequestResponse createIHttpRequestResponse(final byte[] request,
      final byte[] response, final IHttpService service) {
    return new IHttpRequestResponse() {
      @Override
      public byte[] getRequest() {
        return request;
      }

      @Override
      public void setRequest(byte[] message) {
      }

      @Override
      public byte[] getResponse() {
        return response;
      }

      @Override
      public void setResponse(byte[] message) {
      }

      @Override
      public String getComment() {
        return null;
      }

      @Override
      public void setComment(String comment) {
      }

      @Override
      public String getHighlight() {
        return null;
      }

      @Override
      public void setHighlight(String color) {
      }

      @Override
      public IHttpService getHttpService() {
        return service;
      }

      @Override
      public void setHttpService(IHttpService httpService) {
      }
    };
  }

  public static LogEntry createLogEntry() {
    return createLogEntry(1, createIHttpRequestResponse());
  }

  public static LogEntry createLogEntry(final int number, final String requestName) {
    final var logEntry = new LogEntry(number);
    logEntry.setRequestName(requestName);
    return logEntry;
  }

  public static LogEntry createLogEntry(final int number, final byte[] request) {
    return createLogEntry(number, createIHttpRequestResponse(request, null, null));
  }

  public static LogEntry createLogEntry(final int number,
      final IHttpRequestResponse requestResponse) {
    final var logEntry = new LogEntry(number);
    logEntry.setRequestName("top");
    logEntry.setUrl("https://example.com");
    logEntry.setMethod("GET");
    logEntry.setStatusCode((short) 200);
    logEntry.setMime("HTML");
    logEntry.setExtension("html");
    logEntry.setRequestResponse(requestResponse);
    logEntry.setRemark("test");
    return logEntry;
  }

  public static LogEntry createEmptyLogEntry() {
    return new LogEntry(1);
  }

  public static IRequestInfo createIRequestInfo(final String method, final URL url,
      final List<IParameter> parameters) {
    return new IRequestInfo() {
      @Override
      public String getMethod() {
        return method;
      }

      @Override
      public URL getUrl() {
        return url;
      }

      @Override
      public List<String> getHeaders() {
        return null;
      }

      @Override
      public List<IParameter> getParameters() {
        return parameters;
      }

      @Override
      public int getBodyOffset() {
        return 0;
      }

      @Override
      public byte getContentType() {
        return 0;
      }
    };
  }

  public static IParameter createIParameter(final byte type, final String name) {
    return new IParameter() {

      @Override
      public byte getType() {
        return type;
      }

      @Override
      public String getName() {
        return name;
      }

      @Override
      public String getValue() {
        return null;
      }

      @Override
      public int getNameStart() {
        return 0;
      }

      @Override
      public int getNameEnd() {
        return 0;
      }

      @Override
      public int getValueStart() {
        return 0;
      }

      @Override
      public int getValueEnd() {
        return 0;
      }
    };
  }
}
