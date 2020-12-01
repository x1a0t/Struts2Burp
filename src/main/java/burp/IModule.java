package burp;

import module.Util;

import java.net.URL;
import java.util.ArrayList;
import java.util.List;

public class IModule {
    public IExtensionHelpers helpers;
    public IBurpExtenderCallbacks callbacks;
    public IHttpRequestResponse iHttpRequestResponse;
    public IRequestInfo requestInfo;
    public byte[] request;

    public IHttpService httpService;
    public URL url;
    public String detail;
    public String severity;

    public String randomMark = Util.getRandomString(16);
    public String[] injectMark = new String[]{randomMark.substring(0, 9), randomMark.substring(9, 16)};

    public void init(IHttpRequestResponse iHttpRequestResponse, IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers) {
        this.helpers = helpers;
        this.callbacks = callbacks;
        this.iHttpRequestResponse = iHttpRequestResponse;
        this.requestInfo = helpers.analyzeRequest(iHttpRequestResponse);
        this.request = iHttpRequestResponse.getRequest();

        this.httpService = iHttpRequestResponse.getHttpService();
        this.url = helpers.analyzeRequest(iHttpRequestResponse).getUrl();
        this.detail = "No detail";
        this.severity = "High";
    }

    public IScanIssue start() {
        return null;
    }

    public boolean check() {
        return this.check(randomMark);
    }

    public boolean check(String mark) {
        IHttpRequestResponse newHttpRequestResponse = callbacks.makeHttpRequest(httpService, request);
        this.iHttpRequestResponse = newHttpRequestResponse;
        byte[] response = newHttpRequestResponse.getResponse();
        String responseText = helpers.bytesToString(response);

        return responseText.contains(mark);
    }

    public IScanIssue creatCustomScanIssue() {
        String[] tmp = this.getClass().getName().split("\\.");
        String moduleName = tmp[tmp.length-1];
        String name = "[Seagull] " + moduleName;
        return new CustomScanIssue(name, url, httpService, new IHttpRequestResponse[]{iHttpRequestResponse}, detail, severity);
    }

}
