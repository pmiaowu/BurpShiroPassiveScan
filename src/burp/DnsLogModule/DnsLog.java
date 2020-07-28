package burp.DnsLogModule;

import burp.IBurpExtenderCallbacks;

import burp.DnsLogModule.ExtensionMethod.*;

public class DnsLog {
    private DnsLogInterface dnsLog;

    public DnsLog(IBurpExtenderCallbacks callbacks, String dnsLogClassName) {
        this.setApi(callbacks, dnsLogClassName);
    }

    private DnsLogInterface setApi(IBurpExtenderCallbacks callbacks, String dnsLogClassName) {
        if (dnsLogClassName == null || dnsLogClassName.length() <= 0) {
            throw new IllegalArgumentException("DnsLog模块-请输入要调用的dnsLog插件");
        }

        if (dnsLogClassName.equals("DnsLogCn")) {
            dnsLog = new DnsLogCn(callbacks);
            return dnsLog;
        }

        throw new IllegalArgumentException(String.format("DnsLog模块-对不起您输入的 %s 扩展找不到", dnsLogClassName));
    }

    public DnsLogInterface run() {
        return this.dnsLog;
    }
}
