package models.json;

import burp.IHttpRequestResponse;
import burp.IHttpService;
import java.nio.charset.StandardCharsets;
import models.LogEntry;

public class DummyDataUtils {

  static IHttpService createIHttpService() {
    return createIHttpService("example.com", 443, "https");
  }

  static IHttpService createEmptyIHttpService() {
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

  static IHttpRequestResponse createIHttpRequestResponse() {
    final var request = "request".getBytes(StandardCharsets.UTF_8);
    final var response = "response".getBytes(StandardCharsets.UTF_8);
    return createIHttpRequestResponse(request, response, createIHttpService());
  }

  static IHttpRequestResponse createEmptyIHttpRequestResponse() {
    return createIHttpRequestResponse(null, null, null);
  }

  static IHttpRequestResponse createIHttpRequestResponse(final byte[] request,
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

  static LogEntry createLogEntry() {
    final var requestResponse = createIHttpRequestResponse();
    return new LogEntry(1, "top", "https://example.com", "GET", false, "test", requestResponse);
  }

  static LogEntry createEmptyLogEntry() {
    return new LogEntry(1);
  }
}
