package module.java.detect;

import burp.*;

import java.net.URL;
import java.util.List;

public class Shiro implements IModule {

    public IScanIssue start(IHttpRequestResponse iHttpRequestResponse, IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers) {
        IHttpService httpService = iHttpRequestResponse.getHttpService();
        IRequestInfo requestInfo = helpers.analyzeRequest(iHttpRequestResponse);
        IResponseInfo responseInfo = helpers.analyzeResponse(iHttpRequestResponse.getResponse());
        URL url = requestInfo.getUrl();

        IScanIssue scanIssue = new CustomScanIssue(
                httpService,
                url,
                new IHttpRequestResponse[]{iHttpRequestResponse},
                "Shiro detect",
                "Shiro founded",
                "Information"
        );
        for (ICookie cookie : responseInfo.getCookies()) {
            if (cookie.getName().contains("rememberMe") || cookie.getValue().contains("deleteMe")) {

                return scanIssue;
            }
        }

        List<String> headers = requestInfo.getHeaders();
        for (String header : headers) {
            if (header.contains("rememberMe")) {
                return scanIssue;
            }
        }
        IParameter newParameter = helpers.buildParameter("rememberMe", "1", (byte) 2);
        byte[] newRequest = helpers.updateParameter(iHttpRequestResponse.getRequest(), newParameter);
        IHttpRequestResponse newHttpRequestResponse = callbacks.makeHttpRequest(httpService, newRequest);

        IResponseInfo newResponseInfo = helpers.analyzeResponse(newHttpRequestResponse.getResponse());
        for (ICookie cookie : newResponseInfo.getCookies()) {
            if (cookie.getName().contains("rememberMe") || cookie.getValue().contains("deleteMe")) {
                return scanIssue;
            }
        }

        return null;
    }
}
