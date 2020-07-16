package burp;

import java.util.List;
import java.util.ArrayList;
import java.io.PrintWriter;

import burp.Bootstrap.DomainNameRepeatCheck;
import burp.Application.ShiroFingerprintDetection.ShiroFingerprint;
import burp.Application.ShiroCipherKeyDetection.ShiroCipherKey;

public class BurpExtender implements IBurpExtender, IScannerCheck {

    public static String NAME = "BurpShiroPassiveScan";
    public static String VERSION = "1.0.1 beta";

    private IBurpExtenderCallbacks callbacks;
    private PrintWriter stdout;

    private DomainNameRepeatCheck shiroFrameworkDomainNameRepeatCheck;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.stdout = new PrintWriter(callbacks.getStdout(), true);

        this.shiroFrameworkDomainNameRepeatCheck = new DomainNameRepeatCheck();

        callbacks.setExtensionName(NAME);
        callbacks.registerScannerCheck(this);

        this.stdout.println("===================================");
        this.stdout.println(String.format("%s 加载成功", NAME));
        this.stdout.println(String.format("版本: %s", VERSION));
        this.stdout.println("作者: P喵呜-PHPoop");
        this.stdout.println("QQ: 3303003493");
        this.stdout.println("微信: a3303003493");
        this.stdout.println("GitHub: https://github.com/pmiaowu");
        this.stdout.println("Blog: https://www.yuque.com/pmiaowu");
        this.stdout.println("===================================");
    }

    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) {
        List<IScanIssue> issues = new ArrayList<IScanIssue>();

        String baseRequestHost = baseRequestResponse.getHttpService().getHost();
        int baseRequestPort = baseRequestResponse.getHttpService().getPort();
        String baseRequestDomainName = baseRequestHost + ":" + baseRequestPort;

        if (this.shiroFrameworkDomainNameRepeatCheck.isDomainNameRepeat(baseRequestDomainName)) {
            return null;
        }

        // shiro指纹检测
        ShiroFingerprint shiroFingerprint = new ShiroFingerprint(this.callbacks, baseRequestResponse);
        if (!shiroFingerprint.run().isRunExtension()) {
            return null;
        }

        if (!shiroFingerprint.run().isShiroFingerprint()) {
            return null;
        }

        // 确定是 shiro框架 把该域名加入进数组里面防止下次重复扫描
         this.shiroFrameworkDomainNameRepeatCheck.getDomainNameList().add(baseRequestDomainName);

        // shiro指纹检测-报告输出
        issues.add(shiroFingerprint.run().export());

        // shiro指纹检测-控制台报告输出
        shiroFingerprint.run().consoleExport();

        // shiro加密key检测
        ShiroCipherKey shiroCipherKey = new ShiroCipherKey(this.callbacks, baseRequestResponse, shiroFingerprint);
        if (!shiroCipherKey.run().isShiroCipherKeyExists()) {
            return issues;
        }

        // shiro加密key-报告输出
        issues.add(shiroCipherKey.run().export());

        // shiro加密key-控制台报告输出
        shiroCipherKey.run().consoleExport();

        return issues;
    }

    @Override
    public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
        return null;
    }

    @Override
    public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue) {
        if (existingIssue.getIssueName().equals(newIssue.getIssueName())) {
            return -1;
        } else {
            return 0;
        }
    }
}

