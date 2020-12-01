package module.java.vul;

import burp.IModule;
import burp.IParameter;
import burp.IScanIssue;

import java.net.URLEncoder;
import java.util.List;

public class ELInject extends IModule {
    public int random = (int) (Math.random()*100000);
    public int num = 5;
    public String randomMark = String.valueOf(random * num);

    public String[] pocs = new String[]{
            String.format("%s*%s", random, num),
            String.format("${%s*%s}", random, num),
            String.format("#{%s*%s}", random, num),
    };
    @Override
    public IScanIssue start() {
        List<IParameter> parameters = requestInfo.getParameters();
        for (IParameter parmeter: parameters) {
            if (parmeter.getType() != (byte)4 && parmeter.getType() != (byte)2) {

                for (String poc: pocs) {
                    if (parmeter.getType() == (byte)0) {
                        poc = URLEncoder.encode(poc);
                    }
                    IParameter newParameter = helpers.buildParameter(parmeter.getName(), poc, parmeter.getType());
                    request = helpers.updateParameter(iHttpRequestResponse.getRequest(), newParameter);
                    if (check(randomMark)) {
                        return creatCustomScanIssue();
                    }
                }
            }
        }
        return super.start();
    }
}
