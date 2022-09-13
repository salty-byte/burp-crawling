package controllers;

import burp.IBurpExtenderCallbacks;
import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.IMessageEditor;
import models.LogEntry;

public class LogDetailController {

  private final MessageEditorController messageEditorController;
  private final IMessageEditor requestEditor;
  private final IMessageEditor responseEditor;

  public LogDetailController(final IBurpExtenderCallbacks callbacks) {
    messageEditorController = new MessageEditorController();
    requestEditor = callbacks.createMessageEditor(messageEditorController, false);
    responseEditor = callbacks.createMessageEditor(messageEditorController, false);
  }

  public void clear() {
    messageEditorController.clear();
    requestEditor.setMessage(new byte[0], true);
    responseEditor.setMessage(new byte[0], false);
  }

  public void setMessages(final LogEntry logEntry) {
    if (logEntry == null) {
      clear();
      return;
    }
    setMessages(logEntry.getRequestResponse());
  }

  public void setMessages(final IHttpRequestResponse requestResponse) {
    if (requestResponse == null) {
      clear();
      return;
    }
    setMessages(
        requestResponse.getHttpService(),
        requestResponse.getRequest(),
        requestResponse.getResponse()
    );
  }

  public void setMessages(final IHttpService service, final byte[] request,
      final byte[] response) {
    if (service == null) {
      clear();
      return;
    }

    final byte[] shownRequest = request == null ? new byte[0] : request;
    final byte[] shownResponse = response == null ? new byte[0] : response;
    messageEditorController.setMessages(service, shownRequest, shownResponse);
    requestEditor.setMessage(shownRequest, true);
    responseEditor.setMessage(shownResponse, false);
  }

  public IMessageEditor getRequestEditor() {
    return requestEditor;
  }

  public IMessageEditor getResponseEditor() {
    return responseEditor;
  }
}
