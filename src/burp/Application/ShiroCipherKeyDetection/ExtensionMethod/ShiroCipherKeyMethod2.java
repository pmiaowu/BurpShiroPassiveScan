package burp.Application.ShiroCipherKeyDetection.ExtensionMethod;

import burp.*;

import burp.Application.ShiroFingerprintDetection.ShiroFingerprint;
import org.apache.shiro.codec.Base64;
import org.apache.shiro.crypto.AesCipherService;
import org.apache.shiro.subject.SimplePrincipalCollection;
import org.apache.shiro.util.ByteSource;

import java.io.*;
import java.net.URL;

public class ShiroCipherKeyMethod2 extends ShiroCipherKeyMethodAbstract {
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private PrintWriter stdout;

    private IHttpRequestResponse baseRequestResponse;

    private String[] keys;

    private IHttpRequestResponse shiroFingerprintHttpRequestResponse;

    private String rememberMeCookieName;

    private String responseRememberMeCookieValue;

    private String newRequestRememberMeCookieValue;

    private double similarityRatio = 0.7;

    public ShiroCipherKeyMethod2(IBurpExtenderCallbacks callbacks,
                                 IHttpRequestResponse baseRequestResponse,
                                 String[] keys,
                                 ShiroFingerprint shiroFingerprint) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.stdout = new PrintWriter(callbacks.getStdout(), true);

        this.baseRequestResponse = baseRequestResponse;

        this.keys = keys;

        this.shiroFingerprintHttpRequestResponse = shiroFingerprint.run().getHttpRequestResponse();;

        this.rememberMeCookieName = shiroFingerprint.run().getResponseDefaultRememberMeCookieName();

        this.responseRememberMeCookieValue = shiroFingerprint.run().getResponseDefaultRememberMeCookieValue();

        this.newRequestRememberMeCookieValue = "";

        this.setExtensionName("ShiroCipherKeyMethod2");

        try {
            this.runExtension();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private void runExtension() throws IOException {
        if (this.keys == null || this.keys.length <= 0) {
            throw new IllegalArgumentException("shiro加密key检测扩展-要进行爆破的keys不能为空, 请检查");
        }

        byte[] exp = getBytes(new SimplePrincipalCollection());

        // 加密key检测
        for (String key : keys) {
            // 说明检测到shiro key了
            if (this.isShiroCipherKeyExists()) {
                break;
            }

            this.cipherKeyDetection(key, exp);
        }
        this.taskCompletionConsoleExport();
    }

    /**
     * 任务完成情况控制台输出
     */
    private void taskCompletionConsoleExport() {
        URL baseHttpRequestUrl = this.helpers.analyzeRequest(this.baseRequestResponse).getUrl();
        this.stdout.println("============shiro-key扫描完毕================");
        this.stdout.println(String.format("url: %s", baseHttpRequestUrl));
        this.stdout.println("========================================");
    }

    /**
     * 加密key检测
     */
    private void cipherKeyDetection(String key, byte[] exp) {
        int shiroFingerprintCookieRememberMeNumber = this.getHttpCookieRememberMeNumber(this.shiroFingerprintHttpRequestResponse);
        String shiroFingerprintHttpBody = this.getHttpResponseBody(this.shiroFingerprintHttpRequestResponse);

        // 使用当前可能正确的key-发送可能被此shiro框架成功解密的请求
        String correctRememberMe = this.shiroRememberMeEncrypt(key, exp);
        IHttpRequestResponse newHttpRequestResponse1 = this.getNewHttpRequestResponse(correctRememberMe, 3);

        // 判断shiro指纹的请求与当前可能正确key的请求相似度是否差不多一致
        String newHttpBody1 = this.getHttpResponseBody(newHttpRequestResponse1);
        double htmlSimilarityRatio1 = this.getSimilarityRatio(shiroFingerprintHttpBody, newHttpBody1);
        if (this.similarityRatio > htmlSimilarityRatio1) {
            URL newHttpRequestUrl1 = this.helpers.analyzeRequest(newHttpRequestResponse1).getUrl();
            String newHttpRequestMethod1 = this.helpers.analyzeRequest(newHttpRequestResponse1.getRequest()).getMethod();
            int newHttpResponseStatusCode1 = this.helpers.analyzeResponse(newHttpRequestResponse1.getResponse()).getStatusCode();

            this.stdout.println("");
            this.stdout.println("===========页面相似度-debug============");
            this.stdout.println("看到这个说明原请求与发送payload的新请求页面相似度低于“表示匹配成功的页面相似度”");
            this.stdout.println("出现这个可能是因为请求太快waf封了");
            this.stdout.println("也可能是相似度匹配有bug");
            this.stdout.println("请联系作者进行排查");
            this.stdout.println("相关变量: htmlSimilarityRatio1");
            this.stdout.println(String.format("负责检测的插件: %s", this.getExtensionName()));
            this.stdout.println(String.format("表示匹配成功的页面相似度: %s", this.similarityRatio));
            this.stdout.println(String.format("实际两个页面的相似度: %s", htmlSimilarityRatio1));
            this.stdout.println(String.format("url: %s", newHttpRequestUrl1));
            this.stdout.println(String.format("请求方法: %s", newHttpRequestMethod1));
            this.stdout.println(String.format("页面http状态: %d", newHttpResponseStatusCode1));
            this.stdout.println(String.format("对应的Cookie键: %s", this.rememberMeCookieName));
            this.stdout.println(String.format("对应的Cookie值: %s", correctRememberMe));
            this.stdout.println(String.format("Shiro加密key: %s", key));
            this.stdout.println("===================================");
            this.stdout.println("");
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
        String errorRememberMe = this.shiroRememberMeEncrypt(errorKey, exp);
        IHttpRequestResponse newHttpRequestResponse2 = this.getNewHttpRequestResponse(errorRememberMe, 3);

        // 判断shiro指纹的请求与当前必定错误的请求相似度是否差不多一致
        String newHttpBody2 = this.getHttpResponseBody(newHttpRequestResponse2);
        double htmlSimilarityRatio2 = this.getSimilarityRatio(shiroFingerprintHttpBody, newHttpBody2);
        if (this.similarityRatio > htmlSimilarityRatio2) {
            URL newHttpRequestUrl2 = this.helpers.analyzeRequest(newHttpRequestResponse2).getUrl();
            String newHttpRequestMethod2 = this.helpers.analyzeRequest(newHttpRequestResponse2.getRequest()).getMethod();
            int newHttpResponseStatusCode2 = this.helpers.analyzeResponse(newHttpRequestResponse2.getResponse()).getStatusCode();

            this.stdout.println("");
            this.stdout.println("===========页面相似度-debug============");
            this.stdout.println("看到这个说明原请求与发送payload的新请求页面相似度低于“表示匹配成功的页面相似度”");
            this.stdout.println("出现这个可能是因为请求太快waf封了");
            this.stdout.println("也可能是相似度匹配有bug");
            this.stdout.println("请联系作者进行排查");
            this.stdout.println("相关变量: htmlSimilarityRatio2");
            this.stdout.println(String.format("负责检测的插件: %s", this.getExtensionName()));
            this.stdout.println(String.format("表示匹配成功的页面相似度: %s", this.similarityRatio));
            this.stdout.println(String.format("实际两个页面的相似度: %s", htmlSimilarityRatio1));
            this.stdout.println(String.format("url: %s", newHttpRequestUrl2));
            this.stdout.println(String.format("请求方法: %s", newHttpRequestMethod2));
            this.stdout.println(String.format("页面http状态: %d", newHttpResponseStatusCode2));
            this.stdout.println(String.format("对应的Cookie键: %s", this.rememberMeCookieName));
            this.stdout.println(String.format("对应的Cookie值: %s", errorRememberMe));
            this.stdout.println(String.format("Shiro加密key: %s", errorKey));
            this.stdout.println("===================================");
            this.stdout.println("");
            return;
        }

        // 判断当前必定错误的请求-是否被此shiro框架解密
        int newHttpCookieRememberMeNumber2 = this.getHttpCookieRememberMeNumber(newHttpRequestResponse2);
        if(newHttpCookieRememberMeNumber2 < shiroFingerprintCookieRememberMeNumber) {
            return;
        }

        // 设置问题详情
        this.setIssuesDetail(newHttpRequestResponse1, key, correctRememberMe);
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
                if (c.getValue().equals(this.responseRememberMeCookieValue)) {
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

        double htmlSimilarityRatio = this.getSimilarityRatio(shiroFingerprintHttpBody, newHttpBody);
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
     * 两个字符串相似度匹配
     * @param str
     * @param target
     * @return double
     */
    private static double getSimilarityRatio(String str, String target) {
        if (str.equals(target)) {
            return 1;
        }

        int d[][]; // 矩阵
        int n = str.length();
        int m = target.length();
        int i; // 遍历str的
        int j; // 遍历target的
        char ch1; // str的
        char ch2; // target的
        int temp; // 记录相同字符,在某个矩阵位置值的增量,不是0就是1
        if (n == 0 || m == 0) {
            return 0;
        }
        d = new int[n + 1][m + 1];
        for (i = 0; i <= n; i++) { // 初始化第一列
            d[i][0] = i;
        }

        for (j = 0; j <= m; j++) { // 初始化第一行
            d[0][j] = j;
        }

        for (i = 1; i <= n; i++) { // 遍历str
            ch1 = str.charAt(i - 1);
            // 去匹配target
            for (j = 1; j <= m; j++) {
                ch2 = target.charAt(j - 1);
                if (ch1 == ch2 || ch1 == ch2 + 32 || ch1 + 32 == ch2) {
                    temp = 0;
                } else {
                    temp = 1;
                }
                // 左边+1,上边+1, 左上角+temp取最小
                d[i][j] = Math.min(Math.min(d[i - 1][j] + 1, d[i][j - 1] + 1), d[i - 1][j - 1] + temp);
            }
        }

        return (1 - (double) d[n][m] / Math.max(str.length(), target.length()));
    }

    /**
     * 设置问题详情
     */
    private void setIssuesDetail(IHttpRequestResponse httpRequestResponse, String key, String correctRememberMe) {
        this.setShiroCipherKeyExists();
        this.setCipherKey(key);
        this.setHttpRequestResponse(httpRequestResponse);
        this.setNewRequestRememberMeCookieValue(correctRememberMe);
    }

    private void setNewRequestRememberMeCookieValue(String value) {
        this.newRequestRememberMeCookieValue = value;
    }

    private String getNewRequestRememberMeCookieValue() {
        return this.newRequestRememberMeCookieValue;
    }

    private static byte[] getBytes(Object obj) throws IOException {
        ByteArrayOutputStream byteArrayOutputStream = null;
        ObjectOutputStream objectOutputStream = null;
        byteArrayOutputStream = new ByteArrayOutputStream();
        objectOutputStream = new ObjectOutputStream(byteArrayOutputStream);
        objectOutputStream.writeObject(obj);
        objectOutputStream.flush();
        return byteArrayOutputStream.toByteArray();
    }

    private static String shiroRememberMeEncrypt(String key, byte[] objectBytes) {
        Base64 B64 = new Base64();
        byte[] keyDecode = B64.decode(key);
        AesCipherService cipherService = new AesCipherService();
        ByteSource byteSource = cipherService.encrypt(objectBytes, keyDecode);
        byte[] value = byteSource.getBytes();
        return new String(B64.encode(value));
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
        String str4 = String.format("CookieValue: %s <br/>",this.getNewRequestRememberMeCookieValue());
        String str5 = String.format("ShiroCipherKey: %s <br/>", this.getCipherKey());
        String str6 = String.format("=====================================<br/>");

        String detail = str1 + str2 + str3 + str4 + str5 + str6;

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
