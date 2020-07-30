package burp.DnsLogModule;

import burp.IBurpExtenderCallbacks;

import burp.DnsLogModule.ExtensionMethod.*;

public class DnsLog {
    private DnsLogInterface dnsLog;

    public DnsLog(IBurpExtenderCallbacks callbacks, String callClassName) {
        this.setApi(callbacks, callClassName);
    }

    private DnsLogInterface setApi(IBurpExtenderCallbacks callbacks, String callClassName) {
        if (callClassName == null || callClassName.length() <= 0) {
            throw new IllegalArgumentException("DnsLog模块-请输入要调用的dnsLog插件");
        }

        if (callClassName.equals("DnsLogCn")) {
            this.dnsLog = new DnsLogCn(callbacks);
            return this.dnsLog;
        }

        throw new IllegalArgumentException(String.format("DnsLog模块-对不起您输入的 %s 扩展找不到", callClassName));
    }

    public DnsLogInterface run() {
        return this.dnsLog;
    }
}
