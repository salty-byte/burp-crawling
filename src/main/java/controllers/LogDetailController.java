package controllers;

import burp.IBurpExtenderCallbacks;
import burp.IHttpService;
import burp.IMessageEditor;

public class LogDetailController {

  private final MessageEditorController messageEditorController;
  private final IMessageEditor requestEditor;
  private final IMessageEditor responseEditor;

  public LogDetailController(final IBurpExtenderCallbacks callbacks) {
    messageEditorController = new MessageEditorController();
    requestEditor = callbacks.createMessageEditor(messageEditorController, false);
    responseEditor = callbacks.createMessageEditor(messageEditorController, false);
  }

  public void update(IHttpService service, byte[] request, byte[] response) {
    messageEditorController.update(service, request, response);
    requestEditor.setMessage(request, true);
    responseEditor.setMessage(response, false);
  }

  public IMessageEditor getRequestEditor() {
    return requestEditor;
  }

  public IMessageEditor getResponseEditor() {
    return responseEditor;
  }
}
