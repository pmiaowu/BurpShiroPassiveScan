package burp.Application.ShiroFingerprintDetection.ExtensionMethod;

import java.net.URL;
import java.io.PrintWriter;

import burp.IBurpExtenderCallbacks;
import burp.IHttpRequestResponse;
import burp.IExtensionHelpers;
import burp.IHttpService;
import burp.IParameter;
import burp.ICookie;
import burp.IScanIssue;

import burp.CustomScanIssue;

public class ShiroFingerprintType1 extends ShiroFingerprintTypeAbstract {
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;

    private IHttpRequestResponse baseRequestResponse;

    private String rememberMeCookieName = "rememberMe";
    private String rememberMeCookieValue = "1";

    public ShiroFingerprintType1(IBurpExtenderCallbacks callbacks, IHttpRequestResponse baseRequestResponse) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();

        this.baseRequestResponse = baseRequestResponse;

        this.setExtensionName("ShiroFingerprintType1");

        this.runConditionCheck();
    }

    private void runConditionCheck() {
        this.registerExtension();
    }

    public void runExtension() {
        if (!this.isRunExtension()) {
            return;
        }

        IHttpService httpService = this.baseRequestResponse.getHttpService();

        IParameter newParameter = this.helpers.buildParameter(this.rememberMeCookieName, this.rememberMeCookieValue, (byte)2);
        byte[] newRequest = this.helpers.updateParameter(this.baseRequestResponse.getRequest(), newParameter);
        IHttpRequestResponse newHttpRequestResponse = this.callbacks.makeHttpRequest(httpService, newRequest);

        this.setHttpRequestResponse(newHttpRequestResponse);

        for (ICookie c : this.helpers.analyzeResponse(newHttpRequestResponse.getResponse()).getCookies()) {
            if (c.getName().equals(this.rememberMeCookieName)) {
                this.setShiroFingerprint();

                this.setRequestDefaultRememberMeCookieName(this.rememberMeCookieName);
                this.setRequestDefaultRememberMeCookieValue(this.rememberMeCookieValue);

                this.setResponseDefaultRememberMeCookieName(c.getName());
                this.setResponseDefaultRememberMeCookieValue(c.getValue());
                break;
            }
        }
    }

    @Override
    public IScanIssue export() {
        if (!this.isRunExtension()) {
            return null;
        }

        if (!this.isShiroFingerprint()) {
            return null;
        }

        IHttpRequestResponse newHttpRequestResponse = this.getHttpRequestResponse();
        URL newHttpRequestUrl = this.helpers.analyzeRequest(newHttpRequestResponse).getUrl();

        String str1 = String.format("<br/>============ShiroFingerprintDetail============<br/>");
        String str2 = String.format("ExtensionMethod: %s <br/>", this.getExtensionName());
        String str3 = String.format("RequestCookiePayload: %s=%s <br/>",
                this.getRequestDefaultRememberMeCookieName(),
                this.getRequestDefaultRememberMeCookieValue());
        String str4 = String.format("ResponseReturnCookie: %s=%s <br/>",
                this.getResponseDefaultRememberMeCookieName(),
                this.getResponseDefaultRememberMeCookieValue());
        String str5 = String.format("=====================================<br/>");

        String detail = str1 + str2 + str3 + str4 + str5;

        return new CustomScanIssue(
                newHttpRequestResponse.getHttpService(),
                newHttpRequestUrl,
                new IHttpRequestResponse[] { newHttpRequestResponse },
                "ShiroFramework",
                detail,
                "Information");
    }

    @Override
    public void consoleExport() {
        if (!this.isRunExtension()) {
            return;
        }

        if (!this.isShiroFingerprint()) {
            return;
        }

        IHttpRequestResponse newHttpRequestResponse = this.getHttpRequestResponse();
        URL newHttpRequestUrl = this.helpers.analyzeRequest(newHttpRequestResponse).getUrl();
        String newHttpRequestMethod = this.helpers.analyzeRequest(newHttpRequestResponse.getRequest()).getMethod();
        int newHttpResponseStatusCode = this.helpers.analyzeResponse(newHttpRequestResponse.getResponse()).getStatusCode();

        PrintWriter stdout = new PrintWriter(this.callbacks.getStdout(), true);

        stdout.println("");
        stdout.println("==============shiro指纹详情============");
        stdout.println("你好呀~ (≧ω≦*)喵~");
        stdout.println("这边检测到有一个站点使用了 shiro框架 喵~");
        stdout.println(String.format("负责检测的插件: %s", this.getExtensionName()));
        stdout.println(String.format("url: %s", newHttpRequestUrl));
        stdout.println(String.format("请求方法: %s", newHttpRequestMethod));
        stdout.println(String.format("页面http状态: %d", newHttpResponseStatusCode));
        stdout.println(String.format("请求对应的cookie: %s=%s",
                this.getRequestDefaultRememberMeCookieName(),
                this.getRequestDefaultRememberMeCookieValue()));
        stdout.println(String.format("响应返回的cookie: %s=%s",
                this.getResponseDefaultRememberMeCookieName(),
                this.getResponseDefaultRememberMeCookieValue()));
        stdout.println("详情请查看-Burp Scanner模块-Issue activity界面");
        stdout.println("===================================");
        stdout.println("");
    }
}
