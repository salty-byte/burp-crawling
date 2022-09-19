package models.json;

import burp.IHttpRequestResponse;

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
}
