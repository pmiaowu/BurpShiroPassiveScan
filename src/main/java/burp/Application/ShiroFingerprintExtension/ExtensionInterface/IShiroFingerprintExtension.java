package burp.Application.ShiroFingerprintExtension.ExtensionInterface;

import burp.IScanIssue;
import burp.IHttpRequestResponse;

/**
 * shiro指纹扩展的公共接口
 * 所有的抽象类都要继承它并实现所有的接口
 */
public interface IShiroFingerprintExtension {
    String getExtensionName();

    Boolean isRunExtension();

    Boolean isShiroFingerprint();

    String getRequestDefaultRememberMeCookieName();

    String getRequestDefaultRememberMeCookieValue();

    String getResponseDefaultRememberMeCookieName();

    String getResponseDefaultRememberMeCookieValue();

    IHttpRequestResponse getHttpRequestResponse();

    IScanIssue export();

    void consoleExport();
}
