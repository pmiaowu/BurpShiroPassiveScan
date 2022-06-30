package burp.Application.ShiroFingerprintExtension;

import burp.IHttpRequestResponse;
import burp.IBurpExtenderCallbacks;

import burp.Bootstrap.YamlReader;

import burp.Application.ShiroFingerprintExtension.ExtensionMethod.ShiroFingerprint1;
import burp.Application.ShiroFingerprintExtension.ExtensionMethod.ShiroFingerprint2;
import burp.Application.ShiroFingerprintExtension.ExtensionMethod.ShiroFingerprint3;

import burp.Application.ShiroFingerprintExtension.ExtensionInterface.IShiroFingerprintExtension;

public class ShiroFingerprint {
    private IBurpExtenderCallbacks callbacks;

    private YamlReader yamlReader;

    private IHttpRequestResponse baseRequestResponse;

    private IShiroFingerprintExtension shiroFingerprint;

    public ShiroFingerprint(IBurpExtenderCallbacks callbacks, YamlReader yamlReader, IHttpRequestResponse baseRequestResponse) {
        this.callbacks = callbacks;

        this.yamlReader = yamlReader;

        this.baseRequestResponse = baseRequestResponse;

        this.shiroFingerprint = setShiroFingerprint();
    }

    private IShiroFingerprintExtension setShiroFingerprint() {
        // 原始请求 cookie 的 key 带了 rememberMe 则进入该流程
        ShiroFingerprint3 shiroFingerprint3 = new ShiroFingerprint3(this.callbacks, this.yamlReader, this.baseRequestResponse);
        if (shiroFingerprint3.isRunExtension()) {
            shiroFingerprint3.runExtension();
            return shiroFingerprint3;
        }

        // 原始请求响应返回 cookie 的 value 带了 deleteMe 则进入该流程
        ShiroFingerprint2 shiroFingerprint2 = new ShiroFingerprint2(this.callbacks, this.yamlReader, this.baseRequestResponse);
        if (shiroFingerprint2.isRunExtension()) {
            shiroFingerprint2.runExtension();
            return shiroFingerprint2;
        }

        // 上面的条件都不满足时，进入该流程
        ShiroFingerprint1 shiroFingerprint1 = new ShiroFingerprint1(this.callbacks, this.yamlReader, this.baseRequestResponse);
        shiroFingerprint1.runExtension();
        return shiroFingerprint1;
    }

    public IShiroFingerprintExtension run() {
        return this.shiroFingerprint;
    }
}
