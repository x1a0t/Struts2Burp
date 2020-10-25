package burp;

public interface IModule {
    public IScanIssue start(IHttpRequestResponse iHttpRequestResponse, IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers);
}
