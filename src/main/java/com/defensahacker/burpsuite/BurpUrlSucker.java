/**
 * BurpUrlSucker.java
 *
 * Burpsuite (Montoya version) that finds passively hidden endpoints and urls within any downloaded JavaScript file while browsing a website.
 *
 * Based on previous Perl Script: https://github.com/defensahacker/URLSUCKER
 *
 * (c) 2025 Defensahacker Labs
 */

package com.defensahacker.burpsuite;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.Http;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.repeater.Repeater;
import burp.api.montoya.organizer.Organizer;
import burp.api.montoya.ui.UserInterface;

import javax.swing.*;
import javax.swing.event.MouseInputAdapter;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableModel;
import java.awt.*;
import java.awt.event.*;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.*;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Simple class to hold a discovered URL and its source file
 */
class DiscoveredUrl {
    public final String url;
    public final String sourceFile;
    
    public DiscoveredUrl(String url, String sourceFile) {
        this.url = url;
        this.sourceFile = sourceFile;
    }
    
    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (obj == null || getClass() != obj.getClass()) return false;
        DiscoveredUrl that = (DiscoveredUrl) obj;
        return Objects.equals(url, that.url) && Objects.equals(sourceFile, that.sourceFile);
    }
    
    @Override
    public int hashCode() {
        return Objects.hash(url, sourceFile);
    }
    
    @Override
    public String toString() {
        return url + " (from: " + sourceFile + ")";
    }
}

/**
 * Montoya-style Burp extension that:
 *  - inspects responses (js files / responses containing JS)
 *  - extracts URL-like strings (inspired by the Perl implementation)
 *  - groups results by host and displays them in a custom tab
 *  - clicking a discovered URL sends a request to Repeater (and optionally Organizer)
 */
public class BurpUrlSucker implements BurpExtension
{
    private MontoyaApi api;
    private Http http;
    private Repeater repeater;
    private Organizer organizer;
    private UserInterface ui;

    // Thread-safe map host -> set(DiscoveredUrl)
    private final Map<String, Set<DiscoveredUrl>> discovered = new ConcurrentHashMap<>();

    // UI
    private JFrame frame; // used only for Swing EDT ownership (not added to Burp)
    private JPanel panel;
    private JTable table;
    private DefaultTableModel tableModel;

    // regex patterns (greedy + conservative)
    // greedy: strings that look like "/path/..." inside quotes
    private final Pattern greedyPattern = Pattern.compile("\"([^\"'()\\s:;,]+/[^\"'()\\s:;,]+)\"|'([^\"'()\\s:;,]+/[^\"'()\\s:;,]+)'");
    // conservative: match typical URL-like strings
    private final Pattern conservativePattern = Pattern.compile("\"([-\\w./:?=]+)\"|'([-\\w./:?=]+)'|\\(([-\\w./:?=]+)\\)");

    // whether to use greedy extraction (default true, corresponds with perl $greedy)
    private volatile boolean greedy = true;
    
    // search filter
    private volatile String searchFilter = "";

    @Override
    public void initialize(MontoyaApi montoyaApi)
    {
        this.api = montoyaApi;
        this.http = api.http();
        this.repeater = api.repeater();
        this.organizer = api.organizer();
        this.ui = api.userInterface();

        api.extension().setName("URLSucker (Montoya)");
        api.logging().logToOutput("URLSucker loaded");

        // create UI tab and register
        SwingUtilities.invokeLater(this::createUi);

        // register HTTP handler to inspect responses
        http.registerHttpHandler(new HttpHandler()
        {
            @Override
            public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent requestToBeSent)
            {
                // not used here - just continue with the original request
                return RequestToBeSentAction.continueWith(requestToBeSent);
            }

            @Override
            public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived responseReceived)
            {
                try {
                    inspectResponse(responseReceived);
                } catch (Exception e) {
                    api.logging().logToError(e);
                }
                // Continue with the original response
                return ResponseReceivedAction.continueWith(responseReceived);
            }
        });

        api.logging().logToOutput("URLSucker: HTTP handler registered");
    }

    private void inspectResponse(HttpResponseReceived respReceived)
    {
        // respReceived is already an HttpResponse, so we can use it directly
        if (respReceived == null) return;

        // check if content looks like JavaScript
        String contentType = respReceived.headers().stream().filter(h -> h.name().equalsIgnoreCase("Content-Type"))
                .map(h -> h.value()).findFirst().orElse("");
        boolean looksLikeJs = contentType.toLowerCase().contains("javascript")
                || contentType.toLowerCase().contains("application/x-javascript")
                || contentType.toLowerCase().contains("text/javascript");

        // also inspect by URL path (if initiating request exists)
        String initiatorUrl = null;
        try {
            if (respReceived.initiatingRequest() != null && respReceived.initiatingRequest().headerValue("Host") != null) {
                // construct simple origin -> scheme + host
                // we will try to get full URL by using request data when possible
                HttpRequest initReq = respReceived.initiatingRequest();
                String host = initReq.headerValue("Host");
                boolean https = initReq.httpService().secure();
                initiatorUrl = (https ? "https://" : "http://") + host + initReq.url();
            }
        } catch (Throwable ignored) { /* best-effort */ }

        // also fall back to path-based detection: if URL ends with .js
        boolean urlEndsWithJs = false;
        try {
            if (respReceived.initiatingRequest() != null) {
                String url = respReceived.initiatingRequest().url();
                if (url != null && url.toLowerCase().endsWith(".js")) {
                    urlEndsWithJs = true;
                }
            }
        } catch (Throwable ignored) {}

        if (!(looksLikeJs || urlEndsWithJs)) {
            // skip if not javascript-looking
            return;
        }

        String body = respReceived.bodyToString();
        if (body == null || body.isEmpty()) return;

        // Get the source file URL for tracking
        String sourceFileUrl = "unknown";
        try {
            if (respReceived.initiatingRequest() != null) {
                sourceFileUrl = respReceived.initiatingRequest().url();
                // Extract just the filename from the full URL for cleaner display
                if (sourceFileUrl != null) {
                    String[] parts = sourceFileUrl.split("/");
                    if (parts.length > 0) {
                        String filename = parts[parts.length - 1];
                        // Remove query parameters for cleaner display
                        if (filename.contains("?")) {
                            filename = filename.substring(0, filename.indexOf("?"));
                        }
                        if (!filename.isEmpty()) {
                            sourceFileUrl = filename;
                        }
                    }
                }
            }
        } catch (Exception e) {
            sourceFileUrl = "unknown";
        }

        // extract strings
        List<String> matches = extractUrlsFromText(body);

        // resolve each found string to an absolute URL (if possible) using the origin
        for (String found : matches) {
            try {
                String resolved = resolveUrl(found, respReceived);
                if (resolved == null) continue;
                // group by host
                URI u = new URI(resolved);
                String host = (u.getScheme() == null ? "unknown" : u.getScheme() + "://" + u.getHost());
                DiscoveredUrl discoveredUrl = new DiscoveredUrl(resolved, sourceFileUrl);
                discovered.computeIfAbsent(host, k -> Collections.newSetFromMap(new ConcurrentHashMap<>()))
                        .add(discoveredUrl);
            } catch (Exception e) {
                // ignore parse errors of discovered strings
            }
        }

        // update UI
        SwingUtilities.invokeLater(this::refreshTable);
    }

    private List<String> extractUrlsFromText(String text)
    {
        Set<String> matches = new LinkedHashSet<>();
        String[] lines = text.split("\n");
        for (String line : lines) {
            Matcher m;
            if (greedy) {
                m = greedyPattern.matcher(line);
                while (m.find()) {
                    String a = m.group(1);
                    String b = m.group(2);
                    if (a != null) matches.add(a);
                    if (b != null) matches.add(b);
                }
            } else {
                m = conservativePattern.matcher(line);
                while (m.find()) {
                    for (int i = 1; i <= 3; i++) {
                        String g = m.group(i);
                        if (g != null) matches.add(g);
                    }
                }
            }
        }
        return new ArrayList<>(matches);
    }

    /**
     * Try to resolve a discovered string into an absolute URL using the initiating request (if present).
     * If the discovered string is already absolute, returns as-is.
     */
    private String resolveUrl(String candidate, HttpResponseReceived respReceived)
    {
        // Clean candidate a bit: avoid empty
        candidate = candidate.trim();
        if (candidate.length() < 3) return null;

        // If already absolute
        if (candidate.startsWith("http://") || candidate.startsWith("https://")) {
            return candidate;
        }

        // scheme-relative //host/path
        if (candidate.startsWith("//")) {
            try {
                String scheme = "http:";
                if (respReceived.initiatingRequest() != null) {
                    boolean isSecure = respReceived.initiatingRequest().httpService().secure();
                    String proto = isSecure ? "https" : "http";
                    if (proto != null && proto.equalsIgnoreCase("https")) scheme = "https:";
                }
                return scheme + candidate;
            } catch (Throwable t) {
                return "http:" + candidate;
            }
        }

        // path-absolute starting with '/'
        try {
            if (candidate.startsWith("/")) {
                // get base origin from initiating request
                if (respReceived.initiatingRequest() != null) {
                    String host = respReceived.initiatingRequest().httpService().host();
                    boolean https = respReceived.initiatingRequest().httpService().secure();
                    String origin = (https ? "https://" : "http://") + host;
                    URI base = new URI(origin);
                    URI resolved = base.resolve(candidate);
                    return resolved.toString();
                } else {
                    return candidate; // best effort
                }
            }

            // relative path -> resolve against request path
            if (respReceived.initiatingRequest() != null) {
                boolean isSecure = respReceived.initiatingRequest().httpService().secure();
                String scheme = isSecure ? "https" : "http";
                String host = respReceived.initiatingRequest().httpService().host();
                int port = respReceived.initiatingRequest().httpService().port();
                String baseUriStr = scheme + "://" + host + (port == 80 || port == 443 ? "" : ":" + port) + "/";
                URI base = new URI(baseUriStr);
                URI resolved = base.resolve(candidate);
                return resolved.toString();
            }
        } catch (URISyntaxException e) {
            return null;
        }

        // fallback: return raw candidate
        return candidate;
    }

    private void createUi()
    {
        // Create table model with 3 columns
        String[] columnNames = {"Host", "Path", "Source JS File"};
        tableModel = new DefaultTableModel(columnNames, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false; // Make table read-only
            }
        };
        
        table = new JTable(tableModel);
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        table.setAutoCreateRowSorter(true); // Enable column sorting
        
        // Set column widths
        table.getColumnModel().getColumn(0).setPreferredWidth(200); // Host
        table.getColumnModel().getColumn(1).setPreferredWidth(400); // Path  
        table.getColumnModel().getColumn(2).setPreferredWidth(150); // Source JS File

        // double click sends a simple GET to Repeater
        table.addMouseListener(new MouseAdapter() {
            public void mouseClicked(MouseEvent me) {
                if (me.getClickCount() == 2) {
                    int row = table.rowAtPoint(me.getPoint());
                    if (row >= 0) {
                        String host = (String) table.getValueAt(row, 0);
                        String path = (String) table.getValueAt(row, 1);
                        String fullUrl = host + path;
                        sendToRepeater(fullUrl);
                    }
                }
            }
        });

        // right-click context menu to send to Organizer or copy URL
        table.addMouseListener(new MouseAdapter() {
            public void mouseReleased(MouseEvent e) {
                if (e.isPopupTrigger()) {
                    int row = table.rowAtPoint(e.getPoint());
                    if (row >= 0) {
                        table.setRowSelectionInterval(row, row);
                        String host = (String) table.getValueAt(row, 0);
                        String path = (String) table.getValueAt(row, 1);
                        String fullUrl = host + path;
                        
                        JPopupMenu menu = new JPopupMenu();
                        JMenuItem sendRepeater = new JMenuItem("Send to Repeater");
                        sendRepeater.addActionListener(ae -> sendToRepeater(fullUrl));
                        menu.add(sendRepeater);

                        JMenuItem sendOrganizer = new JMenuItem("Send to Organizer");
                        sendOrganizer.addActionListener(ae -> sendToOrganizer(fullUrl));
                        menu.add(sendOrganizer);

                        JMenuItem copy = new JMenuItem("Copy URL");
                        copy.addActionListener(ae -> {
                            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new java.awt.datatransfer.StringSelection(fullUrl), null);
                        });
                        menu.add(copy);

                        menu.show(table, e.getX(), e.getY());
                    }
                }
            }
        });

        // top toolbar with greedy toggle, search field, and clear button
        JPanel toolbar = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 6));
        JCheckBox greedyBox = new JCheckBox("Greedy extraction", greedy);
        greedyBox.addItemListener(e -> this.greedy = greedyBox.isSelected());
        toolbar.add(greedyBox);

        // Add search field
        toolbar.add(new JLabel("Search:"));
        JTextField searchField = new JTextField(20);
        searchField.addActionListener(e -> {
            this.searchFilter = searchField.getText().toLowerCase();
            refreshTable();
        });
        // Also update on key release for real-time filtering
        searchField.addKeyListener(new KeyAdapter() {
            @Override
            public void keyReleased(KeyEvent e) {
                String newFilter = searchField.getText().toLowerCase();
                if (!newFilter.equals(searchFilter)) {
                    searchFilter = newFilter;
                    refreshTable();
                }
            }
        });
        toolbar.add(searchField);

        JButton clearBtn = new JButton("Clear");
        clearBtn.addActionListener(e -> {
            discovered.clear();
            searchField.setText("");
            searchFilter = "";
            refreshTable();
        });
        toolbar.add(clearBtn);

        // wrap in a panel and register with Burp
        panel = new JPanel(new BorderLayout());
        panel.add(toolbar, BorderLayout.NORTH);
        panel.add(new JScrollPane(table), BorderLayout.CENTER);

        // Register as a Burp suite tab
        // userInterface().registerSuiteTab(title, component)
        ui.registerSuiteTab("URLSucker", panel);
    }

    private void refreshTable()
    {
        // Clear existing table data
        tableModel.setRowCount(0);
        
        // Collect all discovered URLs
        List<DiscoveredUrl> allUrls = new ArrayList<>();
        for (String host : discovered.keySet()) {
            for (DiscoveredUrl discoveredUrl : discovered.get(host)) {
                allUrls.add(discoveredUrl);
            }
        }
        
        // Sort by URL first, then by source file
        allUrls.sort((a, b) -> {
            int urlCompare = a.url.compareTo(b.url);
            return urlCompare != 0 ? urlCompare : a.sourceFile.compareTo(b.sourceFile);
        });
        
        // Apply search filter and populate table
        for (DiscoveredUrl discoveredUrl : allUrls) {
            try {
                URI uri = new URI(discoveredUrl.url);
                String host = (uri.getScheme() != null ? uri.getScheme() + "://" : "") + 
                             (uri.getHost() != null ? uri.getHost() : "unknown");
                String path = uri.getPath() != null ? uri.getPath() : "/";
                if (uri.getQuery() != null) {
                    path += "?" + uri.getQuery();
                }
                
                String searchText = (discoveredUrl.url + " " + discoveredUrl.sourceFile + " " + host + " " + path).toLowerCase();
                
                if (searchFilter.isEmpty() || searchText.contains(searchFilter)) {
                    Object[] rowData = {host, path, discoveredUrl.sourceFile};
                    tableModel.addRow(rowData);
                }
            } catch (URISyntaxException e) {
                // If URL parsing fails, still add the row with the original URL
                String searchText = (discoveredUrl.url + " " + discoveredUrl.sourceFile).toLowerCase();
                if (searchFilter.isEmpty() || searchText.contains(searchFilter)) {
                    Object[] rowData = {"unknown", discoveredUrl.url, discoveredUrl.sourceFile};
                    tableModel.addRow(rowData);
                }
            }
        }
    }

    private void sendToRepeater(String urlStr)
    {
        try {
            // build a simple GET request
            HttpRequest req = HttpRequest.httpRequestFromUrl(urlStr);
            // send to Repeater (the Montoya API exposes a sendToRepeater-like helper)
            // Note: method name may vary slightly by version; look for repeater().sendToRepeater(...)
            repeater.sendToRepeater(req, "URLSucker-" + urlStr);
            api.logging().logToOutput("Sent to Repeater: " + urlStr);
        } catch (Exception e) {
            api.logging().logToError(e);
        }
    }

    private void sendToOrganizer(String urlStr)
    {
        try {
            HttpRequest req = HttpRequest.httpRequestFromUrl(urlStr);
            organizer.sendToOrganizer(req);
            api.logging().logToOutput("Sent to Organizer: " + urlStr);
        } catch (Exception e) {
            api.logging().logToError(e);
        }
    }
}

