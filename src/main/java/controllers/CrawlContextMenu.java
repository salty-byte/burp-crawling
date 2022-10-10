package controllers;

import burp.IContextMenuFactory;
import burp.IContextMenuInvocation;
import java.util.ArrayList;
import java.util.List;
import javax.swing.JMenuItem;

public class CrawlContextMenu implements IContextMenuFactory {

  public static final String ITEM_NAME = "Send to Crawling log";

  private final CrawlHelper crawlHelper;

  public CrawlContextMenu(final CrawlHelper crawlHelper) {
    this.crawlHelper = crawlHelper;
  }

  @Override
  public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
    final var crawlMenuItem = new JMenuItem(ITEM_NAME);
    crawlMenuItem.addActionListener(
        v -> crawlHelper.addLogEntries(invocation.getSelectedMessages()));
    return new ArrayList<>(List.of(crawlMenuItem));
  }
}
