package utils;

import static mocks.DummyDataUtils.createIHttpRequestResponse;
import static mocks.DummyDataUtils.createIParameter;
import static mocks.DummyDataUtils.createIRequestInfo;
import static mocks.DummyDataUtils.createLogEntry;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;

import burp.IExtensionHelpers;
import burp.IParameter;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.List;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

class TsvExporterTest {

  private static IExtensionHelpers helpers;

  @BeforeAll
  static void init() throws MalformedURLException {
    helpers = Mockito.mock(IExtensionHelpers.class);
    final var param1 = List.of(
        createIParameter(IParameter.PARAM_URL, "query1", "1")
    );
    final var param2 = List.of(
        createIParameter(IParameter.PARAM_COOKIE, "cookie1", "aaa"),
        createIParameter(IParameter.PARAM_COOKIE, "cookie2", "bbb"),
        createIParameter(IParameter.PARAM_BODY, "body1", "key"),
        createIParameter(IParameter.PARAM_BODY, "body2", "word")
    );
    final var param3 = List.of(
        createIParameter(IParameter.PARAM_COOKIE, "cookie_sp", "!#$%&'()\"`{+*}>"),
        createIParameter(IParameter.PARAM_BODY, "body_sp", "key\u0000b\u0007c\u008fd")
    );
    final var header1 = List.of(
        "GET /?query1=1 HTTP/1.1",
        "Host: example.com"
    );
    final var header2 = List.of(
        "POST / HTTP/1.1",
        "Host: example.com",
        "Cookie: cookie1=aaa; cookie2=bbb",
        "Referer: https://example.com/?query1=1",
        "Content-Length: 20"
    );
    final var header3 = List.of(
        "GET /?query1=1 HTTP/1.1",
        "Host: example.com",
        "Custom: !\"#$&'\n\t()\u0000b\u0008c\u00801"
    );
    final var info1 = createIRequestInfo("GET", new URL("https://example.com/?query1=1"), param1,
        header1);
    final var info2 = createIRequestInfo("POST", new URL("https://example.com/"), param2, header2);
    final var info3 = createIRequestInfo("POST", new URL("https://example.com/\"!$%%()`@[;+*}?>_"),
        param3, header3);
    final var request1 = "1".getBytes(StandardCharsets.UTF_8);
    final var request2 = "2".getBytes(StandardCharsets.UTF_8);
    final var request3 = "3".getBytes(StandardCharsets.UTF_8);
    Mockito.when(helpers.analyzeRequest(any(), eq(request1))).thenReturn(info1);
    Mockito.when(helpers.analyzeRequest(any(), eq(request2))).thenReturn(info2);
    Mockito.when(helpers.analyzeRequest(any(), eq(request3))).thenReturn(info3);
  }

  @Test
  void testExportToString() {
    final var request1 = createIHttpRequestResponse("1".getBytes(StandardCharsets.UTF_8));
    final var request2 = createIHttpRequestResponse("2".getBytes(StandardCharsets.UTF_8));
    final var logEntries = List.of(
        createLogEntry(1, "TOP", "https://example.com/?query1=1", "GET", request1),
        createLogEntry(2, "TOP>ログイン", "https://example.com/", "POST", request2)
    );
    final var exporter = new TsvExporter(helpers);
    final var expectedArray = new String[]{
        "\"TOP\"\t\"GET\"\t\"https://example.com/?query1=1\"\t\"-\"\t\"-\"\t\"-\"\n",
        "\"\"\t\"\"\t\"\"\t\"Header\"\t\"Host\"\t\"example.com\"\n",
        "\"\"\t\"\"\t\"\"\t\"URL\"\t\"query1\"\t\"1\"\n",
        "\"TOP>ログイン\"\t\"POST\"\t\"https://example.com/\"\t\"-\"\t\"-\"\t\"-\"\n",
        "\"\"\t\"\"\t\"\"\t\"Header\"\t\"Host\"\t\"example.com\"\n",
        "\"\"\t\"\"\t\"\"\t\"Header\"\t\"Referer\"\t\"https://example.com/?query1=1\"\n",
        "\"\"\t\"\"\t\"\"\t\"Header\"\t\"Content-Length\"\t\"20\"\n",
        "\"\"\t\"\"\t\"\"\t\"Cookie\"\t\"cookie1\"\t\"aaa\"\n",
        "\"\"\t\"\"\t\"\"\t\"Cookie\"\t\"cookie2\"\t\"bbb\"\n",
        "\"\"\t\"\"\t\"\"\t\"Body\"\t\"body1\"\t\"key\"\n",
        "\"\"\t\"\"\t\"\"\t\"Body\"\t\"body2\"\t\"word\"\n"
    };
    final var expected = String.join("", expectedArray);
    assertEquals(expected, exporter.exportString(logEntries));
  }

  @Test
  void testExportToStringWhenArgumentsHaveSpecialCharacters() {
    final var request3 = createIHttpRequestResponse("3".getBytes(StandardCharsets.UTF_8));
    final var logEntries = List.of(
        createLogEntry(3, "TOP>記号", "https://example.com/\"!$%%()`@[;+*}?>_", "POST", request3)
    );
    final var exporter = new TsvExporter(helpers);
    final var expectedArray = new String[]{
        "\"TOP>記号\"\t\"POST\"\t\"https://example.com/\"\"!$%%()`@[;+*}?>_\"\t\"-\"\t\"-\"\t\"-\"\n",
        "\"\"\t\"\"\t\"\"\t\"Path\"\t\"1\"\t\"\"\"!$%%()`@[;+*}\"\n",
        "\"\"\t\"\"\t\"\"\t\"Header\"\t\"Host\"\t\"example.com\"\n",
        "\"\"\t\"\"\t\"\"\t\"Header\"\t\"Custom\"\t\"!\"\"#$&'()bc\u00801\"\n",
        "\"\"\t\"\"\t\"\"\t\"Cookie\"\t\"cookie_sp\"\t\"!#$%&'()\"\"`{+*}>\"\n",
        "\"\"\t\"\"\t\"\"\t\"Body\"\t\"body_sp\"\t\"keybc\u008fd\"\n",
    };
    final var expected = String.join("", expectedArray);
    assertEquals(expected, exporter.exportString(logEntries));
  }

  @Test
  void testExportToStringOnlyParameters() {
    final var request1 = createIHttpRequestResponse("1".getBytes(StandardCharsets.UTF_8));
    final var request2 = createIHttpRequestResponse("2".getBytes(StandardCharsets.UTF_8));
    final var logEntries = List.of(
        createLogEntry(1, "TOP", "https://example.com/?query1=1", "GET", request1),
        createLogEntry(2, "TOP>ログイン", "https://example.com/", "POST", request2)
    );
    final var exporter = new TsvExporter(helpers);
    final var expectedArray = new String[]{
        "\"TOP\"\t\"GET\"\t\"https://example.com/?query1=1\"\t\"-\"\t\"-\"\t\"-\"\n",
        "\"\"\t\"\"\t\"\"\t\"URL\"\t\"query1\"\t\"1\"\n",
        "\"TOP>ログイン\"\t\"POST\"\t\"https://example.com/\"\t\"-\"\t\"-\"\t\"-\"\n",
        "\"\"\t\"\"\t\"\"\t\"Body\"\t\"body1\"\t\"key\"\n",
        "\"\"\t\"\"\t\"\"\t\"Body\"\t\"body2\"\t\"word\"\n"
    };
    final var expected = String.join("", expectedArray);
    assertEquals(expected, exporter.exportStringOnlyParameters(logEntries));
  }
}
