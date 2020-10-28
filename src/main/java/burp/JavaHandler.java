package burp;

import module.java.detect.Shiro;
import module.java.vul.*;

import java.util.ArrayList;

public class JavaHandler {
    public static ArrayList<IModule> modules = new ArrayList<IModule>();

    public JavaHandler() {
        modules.add(new Shiro());
    }

    public ArrayList<IScanIssue> passiveScan(IHttpRequestResponse iHttpRequestResponse, IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers) {
        ArrayList<IScanIssue> iScanIssues = new ArrayList<IScanIssue>();

        String path = helpers.analyzeRequest(iHttpRequestResponse).getUrl().getPath().split(";")[0];

        if (path.endsWith(".do") || path.endsWith(".action")) {
            modules.add(new S2_001());
            modules.add(new S2_003_005());
            modules.add(new S2_007());
            modules.add(new S2_008());
            modules.add(new S2_009());
            modules.add(new S2_012());
            modules.add(new S2_013_014());
            modules.add(new S2_015());
            modules.add(new S2_016());
        }

        for (IModule module: modules) {
            module.init(iHttpRequestResponse, callbacks, helpers);
        }

        for (IModule module: modules) {
            IScanIssue scanIssue = module.start();
            if (scanIssue != null) {
                iScanIssues.add(scanIssue);
            }
        }

        return iScanIssues;
    }
}
