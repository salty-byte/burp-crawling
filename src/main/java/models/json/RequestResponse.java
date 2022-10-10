package models.json;

import burp.IHttpRequestResponse;
import burp.IHttpService;

public class RequestResponse {

  private final byte[] request;
  private final byte[] response;
  private final HttpOrigin origin;

  public RequestResponse(final IHttpRequestResponse requestResponse) {
    this.request = requestResponse.getRequest();
    this.response = requestResponse.getResponse();
    final var service = requestResponse.getHttpService();
    origin = service == null ? null : new HttpOrigin(service);
  }

  public byte[] getRequest() {
    return request;
  }

  public byte[] getResponse() {
    return response;
  }

  public HttpOrigin getOrigin() {
    return origin;
  }

  public IHttpRequestResponse toIHttpRequestResponse() {
    return new IHttpRequestResponse() {
      @Override
      public byte[] getRequest() {
        return request;
      }

      @Override
      public void setRequest(byte[] message) {
        // do nothing
      }

      @Override
      public byte[] getResponse() {
        return response;
      }

      @Override
      public void setResponse(byte[] message) {
        // do nothing
      }

      @Override
      public String getComment() {
        return null;
      }

      @Override
      public void setComment(String comment) {
        // do nothing
      }

      @Override
      public String getHighlight() {
        return null;
      }

      @Override
      public void setHighlight(String color) {
        // do nothing
      }

      @Override
      public IHttpService getHttpService() {
        return origin;
      }

      @Override
      public void setHttpService(IHttpService httpService) {
        // do nothing
      }
    };
  }
}
