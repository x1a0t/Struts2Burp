package burp;

import java.net.URL;

public class IModule {
    public String detail = "No detail";
    public String severity = "High";

    public IExtensionHelpers helpers;
    public IBurpExtenderCallbacks callbacks;
    public IHttpRequestResponse iHttpRequestResponse;

    public void init(IHttpRequestResponse iHttpRequestResponse, IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers) {
        this.iHttpRequestResponse = iHttpRequestResponse;
        this.callbacks = callbacks;
        this.helpers = helpers;
    }

    public IScanIssue start() {
        return null;
    }

    public IScanIssue creatCustomScanIssue() {
        String[] tmp = this.getClass().getName().split("\\.");
        String moduleName = tmp[tmp.length-1];
        String name = "[Seagull] " + moduleName;
        IHttpService httpService = iHttpRequestResponse.getHttpService();
        URL url = helpers.analyzeRequest(iHttpRequestResponse).getUrl();
        IHttpRequestResponse[] iHttpRequestResponses = {iHttpRequestResponse};
        return new CustomScanIssue(name, url, httpService, iHttpRequestResponses, detail, severity);
    }

}
