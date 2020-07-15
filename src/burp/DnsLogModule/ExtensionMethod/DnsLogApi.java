package burp.DnsLogModule.ExtensionMethod;

import java.io.IOException;
import java.io.PrintWriter;

import org.apache.http.client.CookieStore;
import org.apache.http.client.protocol.HttpClientContext;
import org.apache.http.cookie.Cookie;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;

import burp.IBurpExtenderCallbacks;

public class DnsLogApi extends DnsLogApiAbstract {
    private IBurpExtenderCallbacks callbacks;

    private String dnslogDomainName;

    private String dnsLogCookieName;
    private String dnsLogCookieValue;

    private CookieStore cookiestore;

    public DnsLogApi(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;

        this.dnslogDomainName = "http://www.dnslog.cn";

        this.setExtensionName("DnsLogApi");

        this.init();
    }

    private void init() {
        CloseableHttpClient httpClient = HttpClients.createDefault();

        HttpClientContext context = HttpClientContext.create();
        HttpGet httpGet = new HttpGet(this.dnslogDomainName + "/getdomain.php");

        CloseableHttpResponse response = null;
        try {
            response = httpClient.execute(httpGet, context);

            // 设置 dnslog 的临时域名
            String temporaryDomainName = EntityUtils.toString(response.getEntity());
            if (temporaryDomainName == null || temporaryDomainName.length() <= 0) {
                throw new IllegalArgumentException("DnsLogApi扩展-获取临时域名失败, 请检查");
            }
            this.setTemporaryDomainName(temporaryDomainName);

            if (context.getCookieStore().getCookies().size() <= 0) {
                throw new IllegalArgumentException("DnsLogApi扩展-dnsLogCookie为空, 无法正常获取dnsLog数据, 请检查");
            }
            this.cookiestore = context.getCookieStore();

            // 获取 dnslog 临时域名 的cookie
            for (Cookie cookie : context.getCookieStore().getCookies()) {
                if (cookie.getName().equals("PHPSESSID")) {
                    this.dnsLogCookieName = cookie.getName();
                    this.dnsLogCookieValue = cookie.getValue();
                    break;
                }
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }finally {
            try {
                response.close();
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }
    }

    @Override
    public String getBodyContent() {
        CloseableHttpClient httpClient = HttpClients.createDefault();

        HttpClientContext context = HttpClientContext.create();
        context.setCookieStore(this.cookiestore);
        HttpGet httpGet = new HttpGet(this.dnslogDomainName + "/getrecords.php");

        CloseableHttpResponse response = null;
        try {
            response = httpClient.execute(httpGet, context);
            String content = EntityUtils.toString(response.getEntity());
            if (content.equals("[]")) {
                return null;
            }
            return content;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }finally {
            try {
                response.close();
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }
    }

    @Override
    public String export() {
        String str1 = String.format("<br/>============dnsLogExtensionDetail============<br/>");
        String str2 = String.format("ExtensionMethod: %s <br/>", this.getExtensionName());
        String str3 = String.format("dnsLogDomainName: %s <br/>", this.dnslogDomainName);
        String str4 = String.format("dnsLogRecordsApi: %s <br/>", this.dnslogDomainName + "/getrecords.php");
        String str5 = String.format("cookie: %s=%s <br/>", this.dnsLogCookieName, this.dnsLogCookieValue);
        String str6 = String.format("dnsLogTemporaryDomainName: %s <br/>", this.getTemporaryDomainName());
        String str7 = String.format("=====================================<br/>");

        String detail = str1 + str2 + str3 + str4 + str5 + str6 + str7;

        return detail;
    }

    @Override
    public void consoleExport() {
        PrintWriter stdout = new PrintWriter(this.callbacks.getStdout(), true);

        stdout.println("");
        stdout.println("===========dnsLog扩展详情===========");
        stdout.println("你好呀~ (≧ω≦*)喵~");
        stdout.println(String.format("被调用的插件: %s", this.getExtensionName()));
        stdout.println(String.format("dnsLog域名: %s", this.dnslogDomainName));
        stdout.println(String.format("dnsLog保存记录的api接口: %s", this.dnslogDomainName + "/getrecords.php"));
        stdout.println(String.format("cookie: %s=%s",
                this.dnsLogCookieName,
                this.dnsLogCookieValue));
        stdout.println(String.format("dnsLog临时域名: %s", this.getTemporaryDomainName()));
        stdout.println("===================================");
        stdout.println("");
    }
}
