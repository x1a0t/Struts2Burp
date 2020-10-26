package module.java.detect;

import burp.*;

import java.util.List;

public class Shiro extends IModule {
    public Shiro() {
        moduleName = "Shiro detect";
    }

    public IScanIssue start() {
        IHttpService httpService = iHttpRequestResponse.getHttpService();
        IRequestInfo requestInfo = helpers.analyzeRequest(iHttpRequestResponse);
        IResponseInfo responseInfo = helpers.analyzeResponse(iHttpRequestResponse.getResponse());

        for (ICookie cookie : responseInfo.getCookies()) {
            if (cookie.getName().contains("rememberMe") || cookie.getValue().contains("deleteMe")) {
                return creatCustomScanIssue();
            }
        }

        List<String> headers = requestInfo.getHeaders();
        for (String header : headers) {
            if (header.contains("rememberMe")) {
                return creatCustomScanIssue();
            }
        }
        IParameter newParameter = helpers.buildParameter("rememberMe", "1", (byte) 2);
        byte[] newRequest = helpers.updateParameter(iHttpRequestResponse.getRequest(), newParameter);
        IHttpRequestResponse newHttpRequestResponse = callbacks.makeHttpRequest(httpService, newRequest);

        IResponseInfo newResponseInfo = helpers.analyzeResponse(newHttpRequestResponse.getResponse());
        for (ICookie cookie : newResponseInfo.getCookies()) {
            if (cookie.getName().contains("rememberMe") || cookie.getValue().contains("deleteMe")) {
                this.iHttpRequestResponse = newHttpRequestResponse;
                return creatCustomScanIssue();
            }
        }

        return null;
    }
}
