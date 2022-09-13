package controllers;

import burp.IHttpService;
import burp.IMessageEditorController;

public class MessageEditorController implements IMessageEditorController {

  private IHttpService service;
  private byte[] request;
  private byte[] response;

  public MessageEditorController() {
    clear();
  }

  public void clear() {
    service = null;
    request = new byte[0];
    response = new byte[0];
  }

  public void setMessages(IHttpService service, byte[] request, byte[] response) {
    this.service = service;
    this.request = request;
    this.response = response;
  }

  @Override
  public IHttpService getHttpService() {
    return service;
  }

  @Override
  public byte[] getRequest() {
    return request;
  }

  @Override
  public byte[] getResponse() {
    return response;
  }
}
