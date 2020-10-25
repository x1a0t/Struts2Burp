package burp;


import java.io.PrintWriter;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;

public class BurpExtender implements IBurpExtender, IScannerCheck {
    public static IBurpExtenderCallbacks callbacks;
    public static IExtensionHelpers helpers;
    public static PrintWriter stdout;
    public static PrintWriter stderr;
    public static ArrayList<URL> filterUrls = new ArrayList<URL>();
    public static String[] blackUrls = {".css", ".js", ".jpg", ".jpeg", ".gif", ".png", ".svg", ".ico", ".json"};


    public String extName = "Seagull";

    public void registerExtenderCallbacks(IBurpExtenderCallbacks iBurpExtenderCallbacks) {
        callbacks = iBurpExtenderCallbacks;
        helpers = callbacks.getHelpers();

        callbacks.setExtensionName(extName);
        callbacks.registerScannerCheck(this);

        stdout = new PrintWriter(callbacks.getStdout(), true);
        stderr = new PrintWriter(callbacks.getStderr(), true);
    }

    public List<IScanIssue> doPassiveScan(IHttpRequestResponse iHttpRequestResponse) {
        ArrayList<IScanIssue> iScanIssues = new ArrayList<IScanIssue>();
        URL url = helpers.analyzeRequest(iHttpRequestResponse).getUrl();

        if (filterUrls.contains(url)) {
            return null;
        }
        filterUrls.add(url);

        String path = url.getPath().split(";")[0];
        for(String ext: blackUrls) {
            if (path.endsWith(ext)) {
                return null;
            }
        }
        //java检测
        String[] javaExtensions = {".jsp", ".jspx", ".do", ".action"};
        for(String ext: javaExtensions) {
            if (path.endsWith(ext)) {
                JavaHandler javaHandler = new JavaHandler();
                iScanIssues = javaHandler.passiveScan(iHttpRequestResponse, callbacks, helpers);
                break;
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
}
