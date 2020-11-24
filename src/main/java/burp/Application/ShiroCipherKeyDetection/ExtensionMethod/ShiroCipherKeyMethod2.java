package burp.Application.ShiroCipherKeyDetection.ExtensionMethod;

import burp.*;

import burp.Application.ShiroFingerprintDetection.ShiroFingerprint;

import burp.Bootstrap.DiffPage;
import burp.Bootstrap.CustomHelpers;

import burp.Bootstrap.Encrypt.EncryptInterface;

import burp.CustomErrorException.DiffPageException;

import burp.CustomErrorException.TaskTimeoutException;
import org.apache.shiro.subject.SimplePrincipalCollection;

import java.io.*;
import java.net.URL;
import java.util.Date;

public class ShiroCipherKeyMethod2 extends ShiroCipherKeyMethodAbstract {
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private PrintWriter stdout;

    private CustomHelpers customHelpers;

    private IHttpRequestResponse baseRequestResponse;

    private Date startDate;
    private int maxExecutionTime;

    private String[] keys;

    private IHttpRequestResponse shiroFingerprintHttpRequestResponse;

    private String rememberMeCookieName;

    private String responseRememberMeCookieValue;

    private String newRequestRememberMeCookieValue;

    private DiffPage diffPage;

    private double similarityRatio = 0.7;

    // 相似度匹配算法,匹配失败的次数
    private int errorNumber = 0;
    private int endErrorNumber = 30;

    // 加密类
    private EncryptInterface encryptClass;

    public ShiroCipherKeyMethod2(IBurpExtenderCallbacks callbacks,
                                 IHttpRequestResponse baseRequestResponse,
                                 String[] keys,
                                 ShiroFingerprint shiroFingerprint,
                                 Date startDate,
                                 int maxExecutionTime,
                                 EncryptInterface encrypt) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.stdout = new PrintWriter(callbacks.getStdout(), true);

        this.customHelpers = new CustomHelpers();

        this.baseRequestResponse = baseRequestResponse;

        this.keys = keys;

        this.shiroFingerprintHttpRequestResponse = shiroFingerprint.run().getHttpRequestResponse();;

        this.rememberMeCookieName = shiroFingerprint.run().getResponseDefaultRememberMeCookieName();

        this.responseRememberMeCookieValue = shiroFingerprint.run().getResponseDefaultRememberMeCookieValue();

        this.newRequestRememberMeCookieValue = "";

        this.startDate = startDate;
        this.maxExecutionTime = maxExecutionTime;

        this.setExtensionName("ShiroCipherKeyMethod2");

        this.diffPage = new DiffPage();

        this.encryptClass = encrypt;

        try {
            this.runExtension();
        } catch (IOException e) {
            throw new RuntimeException(e);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private void runExtension() throws Exception {
        if (this.keys == null || this.keys.length <= 0) {
            throw new IllegalArgumentException("shiro加密key检测扩展-要进行爆破的keys不能为空, 请检查");
        }

        byte[] exp = this.encryptClass.getBytes(new SimplePrincipalCollection());

        // 加密key检测
        for (String key : this.keys) {
            // 说明检测到shiro key了
            if (this.isShiroCipherKeyExists()) {
                return;
            }

            // 如果 相似度匹配算法,匹配失败的次数,超过30次,那么就可以退出了
            // 因为这种情况下,大概率触发waf规则了, 那么就没必要跑剩下的了
            if (this.errorNumber >= this.endErrorNumber) {
                // 抛异常结束任务
                throw new DiffPageException("shiro key scan too many errors");
            }

            // 判断程序是否运行超时
            int startTime = this.customHelpers.getSecondTimestamp(this.startDate);
            int currentTime = this.customHelpers.getSecondTimestamp(new Date());
            int runTime = currentTime - startTime;
            if (runTime >= this.maxExecutionTime) {
                throw new TaskTimeoutException("shiro key scan task timeout");
            }

            this.cipherKeyDetection(key, exp);
        }
    }

    /**
     * 加密key检测
     */
    private void cipherKeyDetection(String key, byte[] exp) {
        int shiroFingerprintCookieRememberMeNumber = this.getHttpCookieRememberMeNumber(this.shiroFingerprintHttpRequestResponse);
        String shiroFingerprintHttpBody = this.getHttpResponseBody(this.shiroFingerprintHttpRequestResponse);

        // 使用当前可能正确的key-发送可能被此shiro框架成功解密的请求
        String correctRememberMe = this.encryptClass.encrypt(key, exp);
        IHttpRequestResponse newHttpRequestResponse1 = this.getNewHttpRequestResponse(correctRememberMe, 3);

        // 判断shiro指纹的请求与当前可能正确key的请求相似度是否差不多一致
        String newHttpBody1 = this.getHttpResponseBody(newHttpRequestResponse1);
        double htmlSimilarityRatio1 = this.diffPage.getRatio(shiroFingerprintHttpBody, newHttpBody1);
        if (this.similarityRatio > htmlSimilarityRatio1) {
            this.errorNumber++;
            return;
        }

        // 判断当前可能正确的请求-是否被此shiro框架解密
        int newHttpCookieRememberMeNumber1 = this.getHttpCookieRememberMeNumber(newHttpRequestResponse1);
        if (newHttpCookieRememberMeNumber1 >= shiroFingerprintCookieRememberMeNumber) {
            return;
        }

        // 二次验证-这样可以减少因为waf造成的大量误报
        // 使用一个必定错误的key-发送一个肯定不会被此shiro框架成功解密的请求
        // 密钥 errorKey 然后 aes 加密 == U2FsdGVkX19xgIigFNCsuy2aXwtskOnJV8rQkrT9D5Y=
        String errorKey = "U2FsdGVkX19xgIigFNCsuy2aXwtskOnJV8rQkrT9D5Y=";
        String errorRememberMe = this.encryptClass.encrypt(errorKey, exp);
        IHttpRequestResponse newHttpRequestResponse2 = this.getNewHttpRequestResponse(errorRememberMe, 3);

        // 判断shiro指纹的请求与当前必定错误的请求相似度是否差不多一致
        String newHttpBody2 = this.getHttpResponseBody(newHttpRequestResponse2);
        double htmlSimilarityRatio2 = this.diffPage.getRatio(shiroFingerprintHttpBody, newHttpBody2);
        if (this.similarityRatio > htmlSimilarityRatio2) {
            this.errorNumber++;
            return;
        }

        // 判断当前必定错误的请求-是否被此shiro框架解密
        int newHttpCookieRememberMeNumber2 = this.getHttpCookieRememberMeNumber(newHttpRequestResponse2);
        if(newHttpCookieRememberMeNumber2 < shiroFingerprintCookieRememberMeNumber) {
            return;
        }

        // 设置问题详情
        this.setIssuesDetail(newHttpRequestResponse1, key, this.encryptClass.getName(), correctRememberMe);
    }

    /**
     * 获取http cookie 记住我出现的次数
     * @param httpRequestResponse
     * @return
     */
    private int getHttpCookieRememberMeNumber(IHttpRequestResponse httpRequestResponse) {
        int number = 0;
        for (ICookie c : this.helpers.analyzeResponse(httpRequestResponse.getResponse()).getCookies()) {
            if (c.getName().equals(this.rememberMeCookieName)) {
                if (c.getValue().equals(this.responseRememberMeCookieValue) || c.getValue().equals("deleteMe")) {
                    number++;
                }
            }
        }
        return number;
    }

    /**
     * 获取新的http请求响应
     * @param rememberMe
     * @param remainingRunNumber 剩余运行次数
     * @return IHttpRequestResponse
     */
    private IHttpRequestResponse getNewHttpRequestResponse(String rememberMe, int remainingRunNumber) {
        IHttpService httpService = this.baseRequestResponse.getHttpService();
        IParameter newParameter = this.helpers.buildParameter(
                this.rememberMeCookieName,
                rememberMe,
                (byte)2);
        byte[] newRequest = this.helpers.updateParameter(this.baseRequestResponse.getRequest(), newParameter);
        IHttpRequestResponse newHttpRequestResponse = this.callbacks.makeHttpRequest(httpService, newRequest);

        if (remainingRunNumber <= 1) {
            return newHttpRequestResponse;
        }
        remainingRunNumber--;

        String shiroFingerprintHttpBody = this.getHttpResponseBody(this.shiroFingerprintHttpRequestResponse);
        String newHttpBody = this.getHttpResponseBody(newHttpRequestResponse);

        double htmlSimilarityRatio = this.diffPage.getRatio(shiroFingerprintHttpBody, newHttpBody);
        if (this.similarityRatio > htmlSimilarityRatio) {
            return this.getNewHttpRequestResponse(rememberMe, remainingRunNumber);
        }

        return newHttpRequestResponse;
    }

    /**
     * 获取响应的Body内容
     * @param httpRequestResponse
     * @return String
     */
    private String getHttpResponseBody(IHttpRequestResponse httpRequestResponse) {
        byte[] response = httpRequestResponse.getResponse();
        IResponseInfo responseInfo = this.helpers.analyzeResponse(response);

        int httpBodyOffset = responseInfo.getBodyOffset();
        int httpBodyLength = response.length - httpBodyOffset;

        String httpBody = null;
        try {
            httpBody = new String(response, httpBodyOffset, httpBodyLength, "UTF-8");
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException(e);
        }
        return httpBody;
    }

    /**
     * 设置问题详情
     */
    private void setIssuesDetail(
            IHttpRequestResponse httpRequestResponse,
            String key,
            String encryptMethod,
            String correctRememberMe) {
        this.setShiroCipherKeyExists();
        this.setCipherKey(key);
        this.setEncryptMethod(encryptMethod);
        this.setHttpRequestResponse(httpRequestResponse);
        this.setNewRequestRememberMeCookieValue(correctRememberMe);
    }

    private void setNewRequestRememberMeCookieValue(String value) {
        this.newRequestRememberMeCookieValue = value;
    }

    private String getNewRequestRememberMeCookieValue() {
        return this.newRequestRememberMeCookieValue;
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
        String str3 = String.format("EncryptMethod: %s <br/>", this.encryptClass.getName());
        String str4 = String.format("CookieName: %s <br/>",this.rememberMeCookieName);
        String str5 = String.format("CookieValue: %s <br/>",this.getNewRequestRememberMeCookieValue());
        String str6 = String.format("ShiroCipherKey: %s <br/>", this.getCipherKey());
        String str7 = String.format("=====================================<br/>");

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

        this.stdout.println("");
        this.stdout.println("===========shiro加密key详情============");
        this.stdout.println("你好呀~ (≧ω≦*)喵~");
        this.stdout.println("这边检测到有一个站点使用了 shiro框架 喵~");
        this.stdout.println(String.format(
                        "注意: 该检测方法, 正确的时候响应包的 %s 会消失, 这表示当前key是正确的",
                        this.rememberMeCookieName));
        this.stdout.println(String.format("负责检测的插件: %s", this.getExtensionName()));
        this.stdout.println(String.format("使用的加密方法: %s", this.encryptClass.getName()));
        this.stdout.println(String.format("url: %s", newHttpRequestUrl));
        this.stdout.println(String.format("请求方法: %s", newHttpRequestMethod));
        this.stdout.println(String.format("页面http状态: %d", newHttpResponseStatusCode));
        this.stdout.println(String.format("对应的Cookie键: %s", this.rememberMeCookieName));
        this.stdout.println(String.format("对应的Cookie值: %s", this.getNewRequestRememberMeCookieValue()));
        this.stdout.println(String.format("Shiro加密key: %s", this.getCipherKey()));
        this.stdout.println("详情请查看-Burp Scanner模块-Issue activity界面");
        this.stdout.println("===================================");
        this.stdout.println("");
    }
}
