package burp;

import java.net.URL;

public class CustomScanIssue implements IScanIssue
{
    public IHttpService httpService;
    public URL url;
    public IHttpRequestResponse[] httpMessages;
    public String name;
    public String detail;
    public String severity;

    public CustomScanIssue(String name, URL url, IHttpService httpService, IHttpRequestResponse[] httpMessages, String detail, String severity) {
        this.name = name;
        this.url = url;
        this.httpService = httpService;
        this.httpMessages = httpMessages;
        this.detail = detail;
        this.severity = severity;
    }

    public URL getUrl() {
        return url;
    }

    public String getIssueName() {
        return name;
    }

    public int getIssueType() {
        return 0;
    }

    public String getSeverity() {
        return severity;
    }

    public String getConfidence() {
        return "Certain";
    }

    public String getIssueBackground() {
        return null;
    }

    public String getRemediationBackground() {
        return null;
    }

    public String getIssueDetail() {
        return detail;
    }

    public String getRemediationDetail() {
        return null;
    }

    public IHttpRequestResponse[] getHttpMessages() {
        return httpMessages;
    }

    public IHttpService getHttpService() {
        return httpService;
    }

}
