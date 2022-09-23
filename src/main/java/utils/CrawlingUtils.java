package utils;

import burp.IExtensionHelpers;
import java.net.URL;
import java.util.HashMap;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;
import models.LogEntry;

public class CrawlingUtils {

  private CrawlingUtils() {
    throw new IllegalStateException("Utility class");
  }

  public static String createUrlString(final URL url) {
    final int port = url.getPort() == -1 ? url.getDefaultPort() : url.getPort();
    return String.format("%s://%s:%s%s", url.getProtocol(), url.getHost(), port, url.getPath());
  }

  public static void applyDuplicatedRequest(final List<LogEntry> entries,
      final IExtensionHelpers helpers) {
    // prepare checklist
    final var checkMap = new HashMap<Integer, String>();
    for (int i = 0; i < entries.size() - 1; i++) {
      final var reqRes = entries.get(i).getRequestResponse();
      if (reqRes == null) {
        continue;
      }
      final var requestInfo = helpers.analyzeRequest(reqRes.getHttpService(), reqRes.getRequest());
      final var paramsStr = requestInfo.getParameters()
          .stream()
          .map(p -> p.getType() + p.getName())
          .sorted()
          .collect(Collectors.joining(","));
      final var urlStr = createUrlString(requestInfo.getUrl());
      final var checkStr = requestInfo.getMethod() + urlStr + paramsStr;
      checkMap.put(i, checkStr);
    }

    // reset duplicated status
    entries.parallelStream().forEach(e -> {
      e.setDuplicated(false);
      e.setDuplicatedMessage("");
    });

    // apply
    for (int i = 0; i < entries.size() - 1; i++) {
      final var checkStr1 = checkMap.remove(i);
      if (checkStr1 == null) {
        continue;
      }

      final var entry1 = entries.get(i);
      for (int j = i + 1; j < entries.size(); j++) {
        final var checkStr2 = checkMap.get(j);
        if (Objects.equals(checkStr1, checkStr2)) {
          final var entry2 = entries.get(j);
          entry2.setDuplicated(true);
          entry2.setDuplicatedMessage("No" + entry1.getNumber());
          checkMap.remove(j);
        }
      }
    }
  }
}