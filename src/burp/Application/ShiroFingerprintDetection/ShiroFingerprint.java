package burp.Application.ShiroFingerprintDetection;

import burp.IBurpExtenderCallbacks;
import burp.IHttpRequestResponse;

import burp.Application.ShiroFingerprintDetection.ExtensionMethod.*;

public class ShiroFingerprint {
    private IBurpExtenderCallbacks callbacks;
    private IHttpRequestResponse baseRequestResponse;

    private ShiroFingerprintTypeInterface shiroFingerprintType;

    public ShiroFingerprint(IBurpExtenderCallbacks callbacks, IHttpRequestResponse baseRequestResponse) {
        this.callbacks = callbacks;

        this.baseRequestResponse = baseRequestResponse;

        this.shiroFingerprintType = setShiroFingerprintType();
    }

    private ShiroFingerprintTypeInterface setShiroFingerprintType() {
        // 原始请求 cookie 的 key 带了 rememberMe 则进入该流程
        ShiroFingerprintType3 shiroFingerprintType3 = new ShiroFingerprintType3(this.callbacks, this.baseRequestResponse);
        if (shiroFingerprintType3.isRunExtension()) {
            shiroFingerprintType3.runExtension();
            return shiroFingerprintType3;
        }

        // 原始请求响应返回 cookie 的 value 带了 deleteMe 则进入该流程
        ShiroFingerprintType2 shiroFingerprintType2 = new ShiroFingerprintType2(this.callbacks, this.baseRequestResponse);
        if (shiroFingerprintType2.isRunExtension()) {
            shiroFingerprintType2.runExtension();
            return shiroFingerprintType2;
        }

        // 上面的条件都不满足时，进入该流程
        ShiroFingerprintType1 shiroFingerprintType1 = new ShiroFingerprintType1(this.callbacks, this.baseRequestResponse);
        shiroFingerprintType1.runExtension();
        return shiroFingerprintType1;
    }

    public ShiroFingerprintTypeInterface run() {
        return this.shiroFingerprintType;
    }
}
