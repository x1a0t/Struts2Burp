package burp;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class IModule {
    public IBurpExtenderCallbacks callbacks;
    public IExtensionHelpers helpers;
    public IHttpRequestResponse iHttpRequestResponse;
    public IRequestInfo requestInfo;
    public IHttpService httpService;
    public byte[] request;

    public URL url;
    public String detail;
    public String severity;
    public String moduleName;

    public String poc;
    public String exp;
    public String randomMark = Util.getRandomString(16);
    public String[] injectMark = new String[]{randomMark.substring(0, 9), randomMark.substring(9, 16)};

    public void init(IHttpRequestResponse iHttpRequestResponse) {
        this.helpers = BurpExtender.helpers;
        this.callbacks = BurpExtender.callbacks;
        this.iHttpRequestResponse = iHttpRequestResponse;
        this.requestInfo = BurpExtender.helpers.analyzeRequest(iHttpRequestResponse);
        this.httpService = iHttpRequestResponse.getHttpService();
        this.request = iHttpRequestResponse.getRequest();



        this.url = BurpExtender.helpers.analyzeRequest(iHttpRequestResponse).getUrl();
        this.detail = "No detail";
        this.severity = "High";
        String[] tmp = this.getClass().getName().split("\\.");
        this.moduleName = tmp[tmp.length-1];
    }

    public IScanIssue start() {
        return null;
    }

    public boolean check() {
        return this.check(randomMark);
    }

    public boolean check(String mark) {
        IHttpRequestResponse newHttpRequestResponse = BurpExtender.callbacks.makeHttpRequest(httpService, request);
        this.iHttpRequestResponse = newHttpRequestResponse;
        byte[] response = newHttpRequestResponse.getResponse();
        String responseText = BurpExtender.helpers.bytesToString(response);
        boolean isVul = responseText.contains(mark);
        IModule vulClass = null;
        if(isVul) {
            vulClass = this;
        }
        addLog(url, iHttpRequestResponse, moduleName, vulClass);
        return isVul;
    }

    public IScanIssue creatCustomScanIssue() {
        String name = String.format("[%s] %s", BurpExtender.extName, moduleName);
        return new CustomScanIssue(name, url, httpService, new IHttpRequestResponse[]{iHttpRequestResponse}, detail, severity);
    }

    public void addLog(URL url, IHttpRequestResponse requestResponse, String payload, IModule vulClass) {
        ExecutorService executorService = Executors.newSingleThreadExecutor();
        executorService.submit(new Runnable() {
            @Override
            public void run() {
                synchronized(BurpExtender.log) {
                    int row = BurpExtender.log.size();
                    BurpExtender.log.add(new LogEntry(url, requestResponse, payload, vulClass));
                    GUI.logTable.getHttpLogTableModel().fireTableRowsInserted(row, row);
                }
            }
        });
//        int row = BurpExtender.log.size();
//        BurpExtender.log.add(new LogEntry(url, requestResponse, payload, vulClass));
//        GUI.logTable.getHttpLogTableModel().fireTableRowsInserted(row, row);
    }

    public byte[] makeExploit() {
        //更新当前请求数据
        requestInfo = helpers.analyzeRequest(iHttpRequestResponse);
        //替换请求包中的poc为exp
        List<String> headers = requestInfo.getHeaders();
        for (String header: headers) {
            if (header.contains(poc)) {
                int i = headers.indexOf(header);
                headers.remove(header);
                headers.add(i, header.replace(poc, exp));
                break;
            }
        }

        int bodyOffset = requestInfo.getBodyOffset();
        byte[] requestBody = Arrays.copyOfRange(request, bodyOffset, request.length);
        byte[] body = helpers.bytesToString(requestBody).replace(poc, exp).getBytes();

        return helpers.buildHttpMessage(headers, body);
    }

}
