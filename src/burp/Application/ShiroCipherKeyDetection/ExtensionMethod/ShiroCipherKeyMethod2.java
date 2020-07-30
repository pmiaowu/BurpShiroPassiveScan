package burp.Application.ShiroCipherKeyDetection.ExtensionMethod;

import burp.*;

import burp.Application.ShiroFingerprintDetection.ShiroFingerprint;
import org.apache.shiro.codec.Base64;
import org.apache.shiro.crypto.AesCipherService;
import org.apache.shiro.subject.SimplePrincipalCollection;
import org.apache.shiro.util.ByteSource;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.io.PrintWriter;
import java.net.URL;

public class ShiroCipherKeyMethod2 extends ShiroCipherKeyMethodAbstract {
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;

    private IHttpRequestResponse baseRequestResponse;

    private String[] keys;

    private String rememberMeCookieName;

    private String responseRememberMeCookieValue;

    private String newRequestRememberMeCookieValue;

    public ShiroCipherKeyMethod2(IBurpExtenderCallbacks callbacks,
                                 IHttpRequestResponse baseRequestResponse,
                                 String[] keys,
                                 ShiroFingerprint shiroFingerprint) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();

        this.baseRequestResponse = baseRequestResponse;

        this.keys = keys;

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
                return;
            }

            this.cipherKeyDetection(key, exp);
        }
    }

    /**
     * 加密key检测
     */
    private void cipherKeyDetection(String key, byte[] exp) throws IOException {
        // 1，构造然后直接发包
        // 2，发包完毕以后判断一下是否还存在 rememberMe 如果不存在说明可能跑到key了
        // 3，流程2通过以后，在随便构造一个包，发过去，如果重新出现了 rememberMe=deleteMe 说明真的跑出来了 key

        IHttpService httpService = this.baseRequestResponse.getHttpService();

        // 使用当前可能正确的key-发送可能被此shiro框架成功解密的请求
        String correctRememberMe = this.shiroRememberMeEncrypt(key, exp);

        IParameter newParameter1 = this.helpers.buildParameter(
                this.rememberMeCookieName,
                correctRememberMe,
                (byte)2);
        byte[] newRequest1 = this.helpers.updateParameter(this.baseRequestResponse.getRequest(), newParameter1);
        IHttpRequestResponse newHttpRequestResponse1 = this.callbacks.makeHttpRequest(httpService, newRequest1);

        // 判断当前可能正确的请求-是否被此shiro框架解密
        for (ICookie c : this.helpers.analyzeResponse(newHttpRequestResponse1.getResponse()).getCookies()) {
            if (c.getName().equals(this.rememberMeCookieName)) {
                if (c.getValue().equals(this.responseRememberMeCookieValue)) {
                    return;
                }
            }
        }

        // 二次验证-这样可以减少因为waf造成的大量误报
        // 使用一个必定错误的key-发送一个肯定不会被此shiro框架成功解密的请求
        // 密钥 errorKey 然后 aes 加密 == U2FsdGVkX19xgIigFNCsuy2aXwtskOnJV8rQkrT9D5Y=
        String errorRememberMe = this.shiroRememberMeEncrypt("U2FsdGVkX19xgIigFNCsuy2aXwtskOnJV8rQkrT9D5Y=", exp);

        IParameter newParameter2 = this.helpers.buildParameter(
                this.rememberMeCookieName,
                errorRememberMe,
                (byte)2);
        byte[] newRequest2 = this.helpers.updateParameter(this.baseRequestResponse.getRequest(), newParameter2);
        IHttpRequestResponse newHttpRequestResponse2 = this.callbacks.makeHttpRequest(httpService, newRequest2);

        // 判断当前必定错误的请求-是否被此shiro框架解密
        Boolean isCheckSuccess = false;
        for (ICookie c : this.helpers.analyzeResponse(newHttpRequestResponse2.getResponse()).getCookies()) {
            if (c.getName().equals(this.rememberMeCookieName)) {
                if (c.getValue().equals(this.responseRememberMeCookieValue)) {
                    isCheckSuccess = true;
                    break;
                }
            }
        }

        if (!isCheckSuccess) {
            return;
        }

        // 设置问题详情
        this.setIssuesDetail(newHttpRequestResponse1, key, correctRememberMe);
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

        PrintWriter stdout = new PrintWriter(this.callbacks.getStdout(), true);

        stdout.println("");
        stdout.println("===========shiro加密key详情============");
        stdout.println("你好呀~ (≧ω≦*)喵~");
        stdout.println("这边检测到有一个站点使用了 shiro框架 喵~");
        stdout.println(String.format(
                        "注意: 该检测方法, 正确的时候响应包的 %s 会消失, 这表示当前key是正确的",
                        this.rememberMeCookieName));
        stdout.println(String.format("负责检测的插件: %s", this.getExtensionName()));
        stdout.println(String.format("url: %s", newHttpRequestUrl));
        stdout.println(String.format("请求方法: %s", newHttpRequestMethod));
        stdout.println(String.format("页面http状态: %d", newHttpResponseStatusCode));
        stdout.println(String.format("对应的Cookie键: %s", this.rememberMeCookieName));
        stdout.println(String.format("对应的Cookie值: %s", this.getNewRequestRememberMeCookieValue()));
        stdout.println(String.format("Shiro加密key: %s", this.getCipherKey()));
        stdout.println("详情请查看-Burp Scanner模块-Issue activity界面");
        stdout.println("===================================");
        stdout.println("");
    }
}
