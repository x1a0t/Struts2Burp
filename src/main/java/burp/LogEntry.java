package burp;

import java.net.URL;

public class LogEntry {
    final IHttpRequestResponse requestResponse;
    final URL url;
    final String method;
    final String status;
    final String payload;
    final IModule vulClass;

    public LogEntry(URL url, IHttpRequestResponse requestResponse, String payload, IModule vulClass) {
        this.url = url;
        this.requestResponse = requestResponse;
        short statusCode = BurpExtender.helpers.analyzeResponse(requestResponse.getResponse()).getStatusCode();
        this.method = BurpExtender.helpers.analyzeRequest(requestResponse.getRequest()).getMethod();
        this.status = Short.toString(statusCode);
        this.payload = payload;
        this.vulClass = vulClass;
    }
}