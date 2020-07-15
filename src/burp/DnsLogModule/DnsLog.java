package burp.DnsLogModule;

import burp.IBurpExtenderCallbacks;

import burp.DnsLogModule.ExtensionMethod.*;

public class DnsLog {
    private DnsLogApiInterface dnsLogApi;

    public DnsLog(IBurpExtenderCallbacks callbacks, String dnsLogClassName) {
        this.setApi(callbacks, dnsLogClassName);
    }

    private DnsLogApiInterface setApi(IBurpExtenderCallbacks callbacks, String dnsLogClassName) {
        if (dnsLogClassName == null || dnsLogClassName.length() <= 0) {
            throw new IllegalArgumentException("DnsLogApi模块-请输入要调用的dnsLog插件");
        }

        if (dnsLogClassName.equals("DnsLogApi")) {
            dnsLogApi = new DnsLogApi(callbacks);
            return dnsLogApi;
        }

        throw new IllegalArgumentException(String.format("DnsLogApi模块-对不起您输入的 %s 扩展找不到", dnsLogClassName));
    }

    public DnsLogApiInterface run() {
        return this.dnsLogApi;
    }
}
