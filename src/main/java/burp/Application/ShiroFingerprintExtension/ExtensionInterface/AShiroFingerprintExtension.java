package burp.Application.ShiroFingerprintExtension.ExtensionInterface;

import burp.IHttpRequestResponse;

/**
 * shiro指纹扩展的抽象类
 * 所有的shiro指纹检测的方法都要继承它并实现所有的接口
 */
public abstract class AShiroFingerprintExtension implements IShiroFingerprintExtension {
    private String extensionName = "";

    private Boolean isRunExtension = false;

    private Boolean isShiroFingerprint = false;

    private String requestRememberMeCookieName = "";
    private String requestRememberMeCookieValue = "";

    private String responseRememberMeCookieName = "";
    private String responseRememberMeCookieValue = "";

    private IHttpRequestResponse newHttpRequestResponse;

    /**
     * 设置扩展名称 (必须的)
     *
     * @param value
     */
    protected void setExtensionName(String value) {
        if (value == null || value.isEmpty()) {
            throw new IllegalArgumentException("shiro指纹扫描扩展-扩展名称不能为空");
        }
        this.extensionName = value;
    }

    /**
     * 扩展名称检查
     * 作用: 让所有不设置扩展名称的扩展无法正常使用, 防止直接调用本类的其他方法, 保证扩展的正常
     */
    private void extensionNameCheck() {
        if (this.extensionName == null || this.extensionName.isEmpty()) {
            throw new IllegalArgumentException("请为该shiro指纹扫描扩展-设置扩展名称");
        }
    }

    /**
     * 获取扩展名称
     *
     * @return String
     */
    @Override
    public String getExtensionName() {
        this.extensionNameCheck();
        return this.extensionName;
    }

    /**
     * 注册插件 (必须的)
     * 扩展在运行之前必须调用该接口注册, 否则将无法调用本类的其他方法
     */
    protected void registerExtension() {
        this.extensionNameCheck();
        this.isRunExtension = true;
    }

    /**
     * 注册扩展检查
     * 作用: 让所有未调用方法 registerExtension() 的接口, 无法使用本类的其他方法, 保证扩展的正常
     */
    private void registerExtensionCheck() {
        if (!this.isRunExtension) {
            throw new IllegalArgumentException("注意: 该指纹模块未注册,无法使用");
        }
    }

    /**
     * 是否运行扩展
     * true  运行
     * false 不运行
     *
     * @return Boolean
     */
    @Override
    public Boolean isRunExtension() {
        return this.isRunExtension;
    }

    /**
     * 设置为shiro指纹
     */
    protected void setShiroFingerprint() {
        this.registerExtensionCheck();
        this.isShiroFingerprint = true;
    }

    /**
     * 是否shiro框架
     *
     * @return Boolean
     */
    @Override
    public Boolean isShiroFingerprint() {
        this.registerExtensionCheck();
        return this.isShiroFingerprint;
    }

    /**
     * 设置请求默认“记住我”的Cookie名
     *
     * @param value
     */
    protected void setRequestDefaultRememberMeCookieName(String value) {
        this.registerExtensionCheck();
        this.requestRememberMeCookieName = value;
    }

    /**
     * 获取请求默认“记住我”的Cookie名
     *
     * @return String
     */
    @Override
    public String getRequestDefaultRememberMeCookieName() {
        this.registerExtensionCheck();
        return this.requestRememberMeCookieName;
    }

    /**
     * 设置请求默认“记住我”的Cookie值
     *
     * @param value
     */
    protected void setRequestDefaultRememberMeCookieValue(String value) {
        this.registerExtensionCheck();
        this.requestRememberMeCookieValue = value;
    }

    /**
     * 获取请求默认“记住我”的Cookie值
     *
     * @return String
     */
    @Override
    public String getRequestDefaultRememberMeCookieValue() {
        this.registerExtensionCheck();
        return this.requestRememberMeCookieValue;
    }

    /**
     * 设置响应默认“记住我”的Cookie名称
     *
     * @param value
     */
    protected void setResponseDefaultRememberMeCookieName(String value) {
        this.registerExtensionCheck();
        this.responseRememberMeCookieName = value;
    }

    /**
     * 获取响应默认“记住我”的Cookie名称
     *
     * @return String
     */
    @Override
    public String getResponseDefaultRememberMeCookieName() {
        this.registerExtensionCheck();
        return this.responseRememberMeCookieName;
    }

    /**
     * 设置响应默认的“记住我”Cookie值
     *
     * @param value
     */
    protected void setResponseDefaultRememberMeCookieValue(String value) {
        this.registerExtensionCheck();
        this.responseRememberMeCookieValue = value;
    }

    /**
     * 获取设置响应默认的“记住我”Cookie值
     *
     * @return
     */
    @Override
    public String getResponseDefaultRememberMeCookieValue() {
        this.registerExtensionCheck();
        return this.responseRememberMeCookieValue;
    }

    /**
     * 设置http请求与响应对象
     *
     * @param httpRequestResponse
     */
    protected void setHttpRequestResponse(IHttpRequestResponse httpRequestResponse) {
        this.registerExtensionCheck();
        this.newHttpRequestResponse = httpRequestResponse;
    }

    /**
     * 获取http请求与响应对象
     *
     * @return IHttpRequestResponse
     */
    @Override
    public IHttpRequestResponse getHttpRequestResponse() {
        this.registerExtensionCheck();
        return this.newHttpRequestResponse;
    }
}