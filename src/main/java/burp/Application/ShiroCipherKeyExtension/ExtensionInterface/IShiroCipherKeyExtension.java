package burp.Application.ShiroCipherKeyExtension.ExtensionInterface;

import burp.IScanIssue;
import burp.IHttpRequestResponse;

/**
 * shiro加密key扩展的公共接口
 * 所有的抽象类都要继承它并实现所有的接口
 */
public interface IShiroCipherKeyExtension {
    String getExtensionName();

    Boolean isShiroCipherKeyExists();

    String getEncryptMethod();

    String getCipherKey();

    IHttpRequestResponse getHttpRequestResponse();

    IScanIssue export();

    void consoleExport();
}
