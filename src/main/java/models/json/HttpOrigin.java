package models.json;

import burp.IHttpService;

public class HttpOrigin implements IHttpService {

  private final String host;
  private final int port;
  private final String protocol;

  public HttpOrigin(final IHttpService service) {
    host = service.getHost();
    port = service.getPort();
    protocol = service.getProtocol();
  }

  public String getHost() {
    return host;
  }

  public int getPort() {
    return port;
  }

  public String getProtocol() {
    return protocol;
  }
}
