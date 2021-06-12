package burp;

import javax.swing.*;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;

public class GUI implements IMessageEditorController {
    private JPanel rootPanel;

    public static HttpLogTable logTable;
    public static IMessageEditor requestViewer;
    public static IMessageEditor responseViewer;
    public static IHttpRequestResponse currentlyDisplayedItem;

    public IModule iModule;

    public GUI() {
        setupUI();
    }

    private void setupUI() {
        JSplitPane splitPanel = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        splitPanel.setDividerLocation(0.5);

        HttpLogTableModel model = new HttpLogTableModel();
        logTable = new HttpLogTable(model);

        JScrollPane scrollPane = new JScrollPane(logTable);
        splitPanel.setTopComponent(scrollPane);

        JTabbedPane tabs = new JTabbedPane();
        requestViewer = BurpExtender.callbacks.createMessageEditor(this, false);
        responseViewer = BurpExtender.callbacks.createMessageEditor(this, false);

        tabs.addTab("Request", requestViewer.getComponent());
        tabs.addTab("Response", responseViewer.getComponent());
        splitPanel.setBottomComponent(tabs);


        BurpExtender.callbacks.customizeUiComponent(logTable);
        BurpExtender.callbacks.customizeUiComponent(splitPanel);
        BurpExtender.callbacks.customizeUiComponent(scrollPane);

        rootPanel = new JPanel();
        rootPanel.setLayout(new BorderLayout());
        splitPanel.setOrientation(JSplitPane.VERTICAL_SPLIT);
        rootPanel.add(splitPanel, BorderLayout.CENTER);

        logTable.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if (e.getButton() == MouseEvent.BUTTON3) {
                    int row = logTable.getSelectedRow();
                    logTable.setRowSelectionInterval(row, row);
                    LogEntry logEntry = BurpExtender.log.get(row);

                    JPopupMenu jPopupMenu = new JPopupMenu();

                    JMenuItem clear_all = new JMenuItem("Clear All");
                    clear_all.addActionListener(event -> {
                        int n = JOptionPane.showConfirmDialog(null, "Are you sure you want to clear the data?", "Struts2Burp Client Prompt", JOptionPane.YES_NO_OPTION);
                        if (n == 0) {
                            BurpExtender.log.clear();
                            logTable.getHttpLogTableModel().fireTableDataChanged();
                            logTable.updateUI();
                            requestViewer.setMessage("".getBytes(), false);
                            responseViewer.setMessage("".getBytes(), false);
                        }
                    });
                    jPopupMenu.add(clear_all);

                    JMenuItem clear_other = new JMenuItem("Clear Other");
                    clear_other.addActionListener(event -> BurpExtender.log.removeIf(logEntry1 -> logEntry1.vulClass == null));
                    jPopupMenu.add(clear_other);

                    if (logEntry.vulClass != null) {
                        JMenuItem exp_in_repeater = new JMenuItem("Exp In Repeater");
                        exp_in_repeater.addActionListener(event -> {
                            byte[] exploit = logEntry.vulClass.makeExploit();
                            IHttpService httpService = logEntry.requestResponse.getHttpService();
                            String protocol = httpService.getProtocol();
                            BurpExtender.callbacks.sendToRepeater(httpService.getHost(), httpService.getPort(), protocol.startsWith("https://"), exploit, null);
                        });
                        jPopupMenu.add(exp_in_repeater);
                    }

                    jPopupMenu.show(logTable, e.getX(), e.getY());
                }
            }
        });
    }

    public JComponent getRootComponent() {
        return rootPanel;
    }

    @Override
    public IHttpService getHttpService() {
        return currentlyDisplayedItem.getHttpService();
    }

    @Override
    public byte[] getRequest() {
        return currentlyDisplayedItem.getRequest();
    }

    @Override
    public byte[] getResponse() {
        return currentlyDisplayedItem.getResponse();
    }

}
