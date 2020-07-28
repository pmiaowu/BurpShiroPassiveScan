package burp.DnsLogModule.ExtensionMethod;

/**
 * DnsLog扩展的抽象类
 * 所有的DnsLog检测的方法都要继承它并实现所有的接口
 */
abstract class DnsLogAbstract implements DnsLogInterface {
    private String extensionName = "";

    private String temporaryDomainName;

    /**
     * 设置扩展名称 (必须的)
     * @param value
     */
    protected void setExtensionName(String value) {
        if (value == null || value.isEmpty()) {
            throw new IllegalArgumentException("DnsLog扩展-扩展名称不能为空");
        }
        this.extensionName = value;
    }

    /**
     * 扩展名称检查
     * 作用: 让所有不设置扩展名称的扩展无法正常使用, 防止直接调用本类的其他方法, 保证扩展的正常
     */
    private void extensionNameCheck() {
        if (this.extensionName == null || this.extensionName.isEmpty()) {
            throw new IllegalArgumentException("请为该DnsLog扩展-设置扩展名称");
        }
    }

    /**
     * 获取扩展名称
     * @return String
     */
    @Override
    public String getExtensionName() {
        this.extensionNameCheck();
        return this.extensionName;
    }

    /**
     * 设置临时域名
     * @param value
     */
    protected void setTemporaryDomainName(String value) {
        this.extensionNameCheck();
        this.temporaryDomainName = value;
    }

    /**
     * 获取临时域名
     * @return String
     */
    @Override
    public String getTemporaryDomainName() {
        this.extensionNameCheck();
        return this.temporaryDomainName;
    }
}
