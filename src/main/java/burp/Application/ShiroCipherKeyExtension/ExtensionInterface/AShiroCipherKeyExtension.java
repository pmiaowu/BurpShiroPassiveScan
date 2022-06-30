package burp.Application.ShiroCipherKeyExtension.ExtensionInterface;

import burp.IHttpRequestResponse;

public abstract class AShiroCipherKeyExtension implements IShiroCipherKeyExtension {
    private String extensionName = "";

    private String cipherKey = "";

    private String encryptMethod = "";

    private Boolean isShiroCipherKeyExists = false;

    private IHttpRequestResponse newHttpRequestResponse;

    /**
     * 设置扩展名称 (必须的)
     *
     * @param value
     */
    protected void setExtensionName(String value) {
        if (value == null || value.isEmpty()) {
            throw new IllegalArgumentException("shiro加密key检测扩展-扩展名称不能为空");
        }
        this.extensionName = value;
    }

    /**
     * 扩展名称检查
     * 作用: 让所有不设置扩展名称的扩展无法正常使用, 防止直接调用本类的其他方法, 保证扩展的正常
     */
    private void extensionNameCheck() {
        if (this.extensionName == null || this.extensionName.isEmpty()) {
            throw new IllegalArgumentException("请为该shiro加密key检测扩展-设置扩展名称");
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
     * 设置为扫描出了shiro加密的密钥key
     */
    protected void setShiroCipherKeyExists() {
        this.extensionNameCheck();
        this.isShiroCipherKeyExists = true;
    }

    /**
     * 是否存在 shiro加密的密钥key
     * true  表示 成功扫描出key
     * false 表示 未能成功扫描出key
     *
     * @return Boolean
     */
    @Override
    public Boolean isShiroCipherKeyExists() {
        this.extensionNameCheck();
        return this.isShiroCipherKeyExists;
    }

    /**
     * 设置程序使用的加密方法
     */
    protected void setEncryptMethod(String value) {
        this.extensionNameCheck();
        this.encryptMethod = value;
    }

    /**
     * 获取加密的方法
     * 例如返回: cbc, gcm 加密算法
     *
     * @return String
     */
    @Override
    public String getEncryptMethod() {
        this.extensionNameCheck();
        return this.encryptMethod;
    }

    /**
     * 设置加密的密钥key
     *
     * @param value
     */
    public void setCipherKey(String value) {
        this.extensionNameCheck();
        this.cipherKey = value;
    }

    /**
     * 获取加密的密钥key
     *
     * @return String
     */
    @Override
    public String getCipherKey() {
        this.extensionNameCheck();
        return this.cipherKey;
    }

    /**
     * 设置http请求与响应对象
     *
     * @param httpRequestResponse
     */
    protected void setHttpRequestResponse(IHttpRequestResponse httpRequestResponse) {
        this.extensionNameCheck();
        this.newHttpRequestResponse = httpRequestResponse;
    }

    /**
     * 获取http请求与响应对象
     *
     * @return IHttpRequestResponse
     */
    @Override
    public IHttpRequestResponse getHttpRequestResponse() {
        this.extensionNameCheck();
        return this.newHttpRequestResponse;
    }
}
