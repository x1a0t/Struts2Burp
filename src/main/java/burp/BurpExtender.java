package burp;


import module.*;

import java.awt.*;
import java.io.PrintWriter;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;

public class BurpExtender implements IBurpExtender, IScannerCheck, ITab {
    public static IBurpExtenderCallbacks callbacks;
    public static IExtensionHelpers helpers;
    public static PrintWriter stdout;
    public static PrintWriter stderr;
    public static ArrayList<URL> filterUrls = new ArrayList<>();
    public static ArrayList<IModule> modules = new ArrayList<>();
    public static final List<LogEntry> log = new ArrayList<>();

    public static String extName = "Struts2Burp";
    public static String banner =
            "[+] https://github.com/x1a0t/Struts2Burp\n" +
            "[+] Load Success!";

    public BurpExtender() {
        modules.add(new S2_001());
        modules.add(new S2_003_005());
        modules.add(new S2_007());
        modules.add(new S2_009());
        modules.add(new S2_012());
        modules.add(new S2_013_014());
        modules.add(new S2_015());
        modules.add(new S2_016());
        modules.add(new S2_032());
        modules.add(new S2_045());
        modules.add(new S2_046());
        modules.add(new S2_057());
        modules.add(new S2_059());
        modules.add(new S2_061());
        modules.add(new Devmode());
    }
    public void registerExtenderCallbacks(IBurpExtenderCallbacks iBurpExtenderCallbacks) {
        callbacks = iBurpExtenderCallbacks;
        helpers = callbacks.getHelpers();

        callbacks.setExtensionName(extName);
        callbacks.registerScannerCheck(this);
        callbacks.addSuiteTab(this);

        stdout = new PrintWriter(callbacks.getStdout(), true);
        stderr = new PrintWriter(callbacks.getStderr(), true);
        stdout.println(banner);
    }

    public List<IScanIssue> doPassiveScan(IHttpRequestResponse iHttpRequestResponse) {
        ArrayList<IScanIssue> iScanIssues = new ArrayList<>();
        URL url = helpers.analyzeRequest(iHttpRequestResponse).getUrl();

        String path = url.getPath().split(";")[0];

        if (path.endsWith(".do") || path.endsWith(".action")) {
            //??????burp????????????????????????
//            if (filterUrls.contains(url)) {
//                return null;
//            }
//            filterUrls.add(url);
            for (IModule module: modules) {
                module.init(iHttpRequestResponse);
            }

            for (IModule module: modules) {
                IScanIssue scanIssue = module.start();
                if (scanIssue != null) {
                    iScanIssues.add(scanIssue);
                }
            }
        }

        return iScanIssues;
    }

    public List<IScanIssue> doActiveScan(IHttpRequestResponse iHttpRequestResponse, IScannerInsertionPoint iScannerInsertionPoint) {
        return null;
    }

    public int consolidateDuplicateIssues(IScanIssue iScanIssue, IScanIssue iScanIssue1) {
        if (iScanIssue.getIssueName().equals(iScanIssue1.getIssueName())) {
            return -1;
        } else {
            return 0;
        }
    }

    @Override
    public String getTabCaption() {
        return extName;
    }

    @Override
    public Component getUiComponent() {
        GUI gui = new GUI();
        return gui.getRootComponent();
    }
}
