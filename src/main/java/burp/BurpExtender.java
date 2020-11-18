package burp;

import java.net.URL;
import java.util.List;
import java.util.ArrayList;
import java.io.PrintWriter;

import burp.Bootstrap.DomainNameRepeat;
import burp.Bootstrap.UrlRepeat;

import burp.Application.ShiroFingerprintDetection.ShiroFingerprint;
import burp.Application.ShiroCipherKeyDetection.ShiroCipherKey;

import burp.CustomErrorException.DiffPageException;
import burp.CustomErrorException.TaskTimeoutException;

public class BurpExtender implements IBurpExtender, IScannerCheck {

    public static String NAME = "ShiroScan";
    public static String VERSION = "1.7.2 beta";

    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private PrintWriter stdout;
    private Tags tags;

    private DomainNameRepeat domainNameRepeat;
    private UrlRepeat urlRepeat;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.stdout = new PrintWriter(callbacks.getStdout(), true);

        this.domainNameRepeat = new DomainNameRepeat();
        this.urlRepeat = new UrlRepeat();
        
        // 标签界面
        this.tags = new Tags(callbacks, NAME);

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

        URL baseHttpRequestUrl = this.helpers.analyzeRequest(baseRequestResponse).getUrl();

        // 基础请求域名构造
        String baseRequestProtocol = baseRequestResponse.getHttpService().getProtocol();
        String baseRequestHost = baseRequestResponse.getHttpService().getHost();
        int baseRequestPort = baseRequestResponse.getHttpService().getPort();
        String baseRequestDomainName = baseRequestProtocol + "://" + baseRequestHost + ":" + baseRequestPort;

        // 域名重复检查
        if (this.domainNameRepeat.check(baseRequestDomainName)) {
            return null;
        }

        // url重复检测-模块运行
        IRequestInfo analyzedIResponseInfo = this.helpers.analyzeRequest(baseRequestResponse.getRequest());
        String baseRequestMethod = analyzedIResponseInfo.getMethod();

        URL baseRequestUrl = this.helpers.analyzeRequest(baseRequestResponse).getUrl();
        String newBaseUrl = this.urlRepeat.RemoveUrlParameterValue(baseRequestUrl.toString());

        // url重复检查
        if (this.urlRepeat.check(baseRequestMethod, newBaseUrl)) {
            return null;
        }

        // 确定以前没有执行过 把该url加入进数组里面防止下次重复扫描
        this.urlRepeat.addMethodAndUrl(baseRequestMethod, newBaseUrl);

        // shiro指纹检测-模块运行
        ShiroFingerprint shiroFingerprint = new ShiroFingerprint(this.callbacks, baseRequestResponse);
        if (!shiroFingerprint.run().isRunExtension()) {
            return null;
        }

        // 检测是否shiro框架
        if (!shiroFingerprint.run().isShiroFingerprint()) {
            return null;
        }

        // 确定是 shiro框架 把该域名加入进HashMap里面防止下次重复扫描
        this.domainNameRepeat.add(baseRequestDomainName);

        // shiro指纹检测-报告输出
        issues.add(shiroFingerprint.run().export());

        // shiro指纹检测-控制台报告输出
        shiroFingerprint.run().consoleExport();

        // 新增shiro key 扫描任务至任务栏面板
        IHttpRequestResponse shiroFingerprintHttpRequestResponse = shiroFingerprint.run().getHttpRequestResponse();
        byte[] shiroFingerprintResponse = shiroFingerprintHttpRequestResponse.getResponse();
        int tagId = this.tags.add(
                shiroFingerprint.run().getExtensionName(),
                this.helpers.analyzeRequest(shiroFingerprintHttpRequestResponse).getMethod(),
                baseRequestUrl.toString(),
                this.helpers.analyzeResponse(shiroFingerprintResponse).getStatusCode() + "",
                "waiting for test results",
                shiroFingerprintHttpRequestResponse
        );

        try {
            // shiro加密key检测-模块运行
            ShiroCipherKey shiroCipherKey = new ShiroCipherKey(
                    this.callbacks,
                    baseRequestResponse,
                    shiroFingerprint,
                    "ShiroCipherKeyMethod2");

            // 检测是否爆破出了shiro加密key
            if (!shiroCipherKey.run().isShiroCipherKeyExists()) {
                // 任务完成情况控制台输出
                this.taskCompletionConsoleExport(baseRequestResponse);

                // 未检查出来key-更新任务状态至任务栏面板
                this.tags.save(
                        tagId,
                        shiroCipherKey.run().getExtensionName(),
                        this.helpers.analyzeRequest(shiroFingerprintHttpRequestResponse).getMethod(),
                        baseRequestUrl.toString(),
                        this.helpers.analyzeResponse(shiroFingerprintResponse).getStatusCode() + "",
                        "[-] not found shiro key",
                        shiroFingerprintHttpRequestResponse
                );
                return issues;
            }

            // shiro加密key-报告输出
            issues.add(shiroCipherKey.run().export());

            // shiro加密key-控制台报告输出
            shiroCipherKey.run().consoleExport();

            // 任务完成情况控制台输出
            this.taskCompletionConsoleExport(baseRequestResponse);

            // 检查出来key-更新任务状态至任务栏面板
            IHttpRequestResponse shiroCipherKeyRequestResponse = shiroCipherKey.run().getHttpRequestResponse();
            byte[] shiroCipherKeyResponse = shiroCipherKeyRequestResponse.getResponse();
            this.tags.save(
                    tagId,
                    shiroCipherKey.run().getExtensionName(),
                    this.helpers.analyzeRequest(shiroCipherKeyRequestResponse).getMethod(),
                    baseRequestUrl.toString(),
                    this.helpers.analyzeResponse(shiroCipherKeyResponse).getStatusCode() + "",
                    "[+] found shiro key:" + shiroCipherKey.run().getCipherKey(),
                    shiroCipherKeyRequestResponse
            );
        } catch (OutOfMemoryError e) {
            /**
             * 如果这里报错了,大概率是因为进行相似度匹配的时候,匹配的两个字符串太长了
             * 超过了 new int[] 数组的长度导致的
             * 报错的文件路径"src/burp/Bootstrap/DiffPage.java"文件 getSimilarityRatio()方法
             * 里面的 "d = new int[n + 1][m + 1];" 长度溢出了
             * 那么只能让他换个url重跑了
             */
            // 将 url重复检测 与 域名重复检测 的内存删除,下次这个站点的请求进来了,还可以尝试重新跑
            this.urlRepeat.delMethodAndUrl(baseRequestMethod, newBaseUrl);
            this.domainNameRepeat.del(baseRequestDomainName);

            // 通知控制台报错
            this.stdout.println("========shiro-key模块错误-内存溢出============");
            this.stdout.println(String.format("url: %s", baseHttpRequestUrl));
            this.stdout.println("请换该站点其它url重新访问");
            this.stdout.println("========================================");

            // 本次任务执行有问题-更新任务状态至任务栏面板
            this.tags.save(
                    tagId,
                    shiroFingerprint.run().getExtensionName(),
                    this.helpers.analyzeRequest(shiroFingerprintHttpRequestResponse).getMethod(),
                    baseRequestUrl.toString(),
                    this.helpers.analyzeResponse(shiroFingerprintResponse).getStatusCode() + "",
                    "shiro key scan out of memory error",
                    shiroFingerprintHttpRequestResponse
            );

            // 报致命异常停止本次执行
            throw new RuntimeException(e);
        } catch (DiffPageException e) {
            // 将 url重复检测 与 域名重复检测 的内存删除,下次这个站点的请求进来了,还可以尝试重新跑
            this.urlRepeat.delMethodAndUrl(baseRequestMethod, newBaseUrl);
            this.domainNameRepeat.del(baseRequestDomainName);

            // 通知控制台报错
            this.stdout.println("========shiro-key模块错误-相似度匹配多次失败============");
            this.stdout.println("看到这个说明原请求与发送payload的新请求页面相似度低于“表示匹配成功的页面相似度”");
            this.stdout.println("出现这个可能是因为请求太快waf封了");
            this.stdout.println("也可能是相似度匹配有bug");
            this.stdout.println("请联系作者进行排查");
            this.stdout.println(String.format("url: %s", baseHttpRequestUrl));
            this.stdout.println("请换该站点其它url重新访问");
            this.stdout.println("========================================");

            // 本次任务执行有问题-更新任务状态至任务栏面板
            this.tags.save(
                    tagId,
                    shiroFingerprint.run().getExtensionName(),
                    this.helpers.analyzeRequest(shiroFingerprintHttpRequestResponse).getMethod(),
                    baseRequestUrl.toString(),
                    this.helpers.analyzeResponse(shiroFingerprintResponse).getStatusCode() + "",
                    "shiro key scan diff page too many errors",
                    shiroFingerprintHttpRequestResponse
            );

            // 报致命异常停止本次执行
            throw new RuntimeException(e);
        } catch (TaskTimeoutException e) {
            // 将 url重复检测 与 域名重复检测 的内存删除,下次这个站点的请求进来了,还可以尝试重新跑
            this.urlRepeat.delMethodAndUrl(baseRequestMethod, newBaseUrl);
            this.domainNameRepeat.del(baseRequestDomainName);

            // 通知控制台报错
            this.stdout.println("========shiro-key模块错误-程序运行超时============");
            this.stdout.println(String.format("url: %s", baseHttpRequestUrl));
            this.stdout.println("请换该站点其它url重新访问");
            this.stdout.println("========================================");

            // 本次任务执行有问题-更新任务状态至任务栏面板
            this.tags.save(
                    tagId,
                    shiroFingerprint.run().getExtensionName(),
                    this.helpers.analyzeRequest(shiroFingerprintHttpRequestResponse).getMethod(),
                    baseRequestUrl.toString(),
                    this.helpers.analyzeResponse(shiroFingerprintResponse).getStatusCode() + "",
                    "shiro key scan task timeout",
                    shiroFingerprintHttpRequestResponse
            );

            // 报致命异常停止本次执行
            throw new RuntimeException(e);
        } finally {
            // 输出跑到的问题给burp
            return issues;
        }
    }

    /**
     * 任务完成情况控制台输出
     */
    private void taskCompletionConsoleExport(IHttpRequestResponse requestResponse) {
        URL httpRequestUrl = this.helpers.analyzeRequest(requestResponse).getUrl();
        this.stdout.println("============shiro-key扫描完毕================");
        this.stdout.println(String.format("url: %s", httpRequestUrl));
        this.stdout.println("========================================");
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