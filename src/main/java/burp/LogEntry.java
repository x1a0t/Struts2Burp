package burp;

import java.net.URL;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Map;

public class LogEntry {
    final IHttpRequestResponse requestResponse;
    final URL url;
    final String method;
    final String status;
    final String vulName;
    final IModule vulClass;

    public LogEntry(URL url, IHttpRequestResponse requestResponse, String vulName, IModule vulClass) {
        this.url = url;
        this.requestResponse = requestResponse;
        short statusCode = BurpExtender.helpers.analyzeResponse(requestResponse.getResponse()).getStatusCode();
        this.method = BurpExtender.helpers.analyzeRequest(requestResponse.getRequest()).getMethod();
        this.status = Short.toString(statusCode);
        this.vulName = vulName;
        this.vulClass = vulClass;
    }
}