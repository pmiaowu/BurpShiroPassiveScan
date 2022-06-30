package burp.Application.ShiroFingerprintExtension.ExtensionMethod;

import burp.*;
import burp.Application.ShiroFingerprintExtension.ExtensionInterface.AShiroFingerprintExtension;
import burp.Bootstrap.YamlReader;

import java.io.PrintWriter;
import java.net.URL;

public class ShiroFingerprint1 extends AShiroFingerprintExtension {
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;

    private YamlReader yamlReader;

    private IHttpRequestResponse baseRequestResponse;

    private String rememberMeCookieName = "rememberMe";
    private String rememberMeCookieValue = "1";

    public ShiroFingerprint1(IBurpExtenderCallbacks callbacks, YamlReader yamlReader, IHttpRequestResponse baseRequestResponse) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();

        this.yamlReader = yamlReader;

        this.baseRequestResponse = baseRequestResponse;

        this.setExtensionName("ShiroFingerprint1");

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

        IParameter newParameter = this.helpers.buildParameter(this.rememberMeCookieName, this.rememberMeCookieValue, (byte) 2);
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

        String shiroFingerprintIssueName = this.yamlReader.getString("application.shiroFingerprintExtension.config.issueName");

        return new CustomScanIssue(
                newHttpRequestUrl,
                shiroFingerprintIssueName,
                0,
                "Information",
                "Certain",
                null,
                null,
                detail,
                null,
                new IHttpRequestResponse[]{newHttpRequestResponse},
                newHttpRequestResponse.getHttpService()
        );
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
