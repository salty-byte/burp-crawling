package utils;

import burp.IExtensionHelpers;
import burp.IParameter;
import java.awt.Toolkit;
import java.awt.datatransfer.StringSelection;
import java.net.URL;
import java.text.SimpleDateFormat;
import java.time.Instant;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import models.LogEntry;

public class CrawlingUtils {

  private static final String NUMBER_MASK = "__N__";

  private CrawlingUtils() {
    throw new IllegalStateException("Utility class");
  }

  public static String findExtension(final URL url) {
    final var pattern = Pattern.compile("/.+\\.([^/.]+)$");
    final var matcher = pattern.matcher(url.getPath());
    return matcher.find() ? matcher.group(1) : "";
  }

  public static String createDateString() {
    final var date = Date.from(Instant.now());
    return new SimpleDateFormat("HH:mm:ss dd MMM yyyy", Locale.US).format(date);
  }

  private static boolean hasDefaultUrlPort(final URL url) {
    final int port = url.getPort();
    final var protocol = url.getProtocol();
    return port == -1
        || ("https".equals(protocol) && port == 443)
        || ("http".equals(protocol) && port == 80);
  }

  public static String createUrlString(final URL url) {
    if (hasDefaultUrlPort(url)) {
      return String.format("%s://%s%s", url.getProtocol(), url.getHost(), url.getPath());
    }
    return String.format("%s://%s:%s%s",
        url.getProtocol(), url.getHost(), url.getPort(), url.getPath());
  }

  public static String createUrlStringWithQuery(final URL url) {
    if (hasDefaultUrlPort(url)) {
      return String.format("%s://%s%s", url.getProtocol(), url.getHost(), url.getFile());
    }
    return String.format("%s://%s:%s%s",
        url.getProtocol(), url.getHost(), url.getPort(), url.getFile());
  }

  private static Map<Integer, String> createCheckMap(final List<LogEntry> entries,
      final IExtensionHelpers helper) {
    final Map<Integer, String> checkMap = new HashMap<>();
    for (int i = 0; i < entries.size(); i++) {
      final var reqRes = entries.get(i).getRequestResponse();
      if (reqRes == null) {
        continue;
      }
      final var requestInfo = helper.analyzeRequest(reqRes.getHttpService(), reqRes.getRequest());
      final var paramStr = requestInfo.getParameters()
          .stream()
          .filter(p -> p.getType() != IParameter.PARAM_COOKIE)
          .map(p -> p.getType() + p.getName())
          .sorted()
          .collect(Collectors.joining());
      final var urlStr = createUrlString(requestInfo.getUrl());
      final var maskedUrlStr = urlStr.replaceAll("/\\d+(/|$)", String.format("/%s$1", NUMBER_MASK));
      final var value = requestInfo.getMethod() + maskedUrlStr + paramStr;
      checkMap.put(i, value);
    }
    return checkMap;
  }

  public static void applySimilarOrDuplicatedRequest(final List<LogEntry> entries,
      final IExtensionHelpers helper) {
    // prepare checklist
    final var checkMap = createCheckMap(entries, helper);

    // clear status
    entries.parallelStream().forEach(e -> {
      e.setDuplicated(false);
      e.setSimilar(false);
      e.setCheckedMessage("");
    });

    // apply
    for (int i = 0; i < entries.size() - 1; i++) {
      final var checkStr1 = checkMap.get(i);
      if (checkStr1 == null) {
        continue;
      }

      final var entry1 = entries.get(i);
      for (int j = 0; j < entries.size(); j++) {
        final var checkStr2 = checkMap.get(j);
        if (checkStr2 == null || i == j) {
          continue;
        }

        if (Objects.equals(checkStr1, checkStr2)) {
          final var entry2 = entries.get(j);
          entry2.setDuplicated(true);
          entry2.setCheckedMessage("No" + entry1.getNumber());
          checkMap.remove(j);
        } else if (checkStr1.startsWith(checkStr2)) {
          final var entry2 = entries.get(j);
          entry2.setSimilar(true);
          entry2.setCheckedMessage("No" + entry1.getNumber());
          checkMap.remove(j);
        }
      }
    }
  }

  public static void applyRequestNameHash(final List<LogEntry> entries) {
    final var mark = "#";
    int count = 0;
    String checkName = "";
    for (final var entry : entries) {
      final var currentRequestName = entry.getRequestName();
      if (currentRequestName == null) {
        count = 0;
        checkName = "";
        continue;
      }

      final var requestName = currentRequestName.split(mark)[0];
      if (!requestName.isEmpty() && requestName.equals(checkName)) {
        count++;
        entry.setRequestName(String.format("%s%s%s", requestName, mark, count));
      } else {
        count = 1;
        checkName = requestName;
        entry.setRequestName(requestName);
      }
    }
  }

  public static void exportToClipBoard(final String message) {
    final var toolkit = Toolkit.getDefaultToolkit();
    final var clipboard = toolkit.getSystemClipboard();
    final var selection = new StringSelection(message);
    clipboard.setContents(selection, selection);
  }
}
