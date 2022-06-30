package burp;

import java.net.URL;
import java.util.List;
import java.util.Arrays;
import java.util.ArrayList;
import java.io.PrintWriter;

import burp.Ui.Tags;

import burp.Bootstrap.YamlReader;
import burp.Bootstrap.CustomBurpUrl;
import burp.Bootstrap.GlobalVariableReader;
import burp.Bootstrap.GlobalPassiveScanVariableReader;

import burp.Application.ShiroFingerprintExtension.ShiroFingerprint;

import burp.Application.ShiroCipherKeyExtension.ShiroCipherKeyThread;
import burp.Application.ShiroCipherKeyExtension.ExtensionInterface.IShiroCipherKeyExtension;

public class BurpExtender implements IBurpExtender, IScannerCheck, IExtensionStateListener {
    public static String NAME = "ShiroScan";
    public static String VERSION = "2.0.0";

    private GlobalVariableReader globalVariableReader;

    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;

    private PrintWriter stdout;
    private PrintWriter stderr;

    private Tags tags;

    private YamlReader yamlReader;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();

        this.stdout = new PrintWriter(callbacks.getStdout(), true);
        this.stderr = new PrintWriter(callbacks.getStderr(), true);

        // 全局变量的数据保存地址
        // 用于在程序执行的过程中能够实时的修改变量数据使用
        this.globalVariableReader = new GlobalVariableReader();

        // 是否卸载扩展
        // 用于卸载插件以后,把程序快速退出去,避免卡顿
        // true = 已被卸载, false = 未卸载
        this.globalVariableReader.putBooleanData("isExtensionUnload", false);

        // 标签界面
        this.tags = new Tags(callbacks, NAME);

        // 配置文件
        this.yamlReader = YamlReader.getInstance(callbacks);

        callbacks.setExtensionName(NAME);
        callbacks.registerScannerCheck(this);
        callbacks.registerExtensionStateListener(this);

        // 基本信息输出
        // 作者拿来臭美用的 ╰(*°▽°*)╯
        this.stdout.println(basicInformationOutput());
    }

    /**
     * 基本信息输出
     */
    private static String basicInformationOutput() {
        String str1 = "===================================\n";
        String str2 = String.format("%s Load the success\n", NAME);
        String str3 = String.format("VERSION: %s\n", VERSION);
        String str4 = "author: pmiaowu\n";
        String str5 = "QQ: 3303003493\n";
        String str6 = "WeChat: a3303003493\n";
        String str7 = "GitHub: https://github.com/pmiaowu\n";
        String str8 = "Blog: https://www.yuque.com/pmiaowu\n";
        String str9 = String.format("downloadLink: %s\n", "https://github.com/pmiaowu/BurpShiroPassiveScan");
        String str10 = "===================================\n";
        String detail = str1 + str2 + str3 + str4 + str5 + str6 + str7 + str8 + str9 + str10;
        return detail;
    }

    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) {
        // 被动扫描器变量共享的数据保存地址
        // 用于在程序执行的过程中能够实时的修改变量数据使用
        GlobalPassiveScanVariableReader globalPassiveScanVariableReader = new GlobalPassiveScanVariableReader();

        List<IScanIssue> issues = new ArrayList<>();

        List<String> domainNameBlacklist = this.yamlReader.getStringList("scan.domainName.blacklist");
        List<String> domainNameWhitelist = this.yamlReader.getStringList("scan.domainName.whitelist");

        // 基础url解析
        CustomBurpUrl baseBurpUrl = new CustomBurpUrl(this.callbacks, baseRequestResponse);

        // 消息等级-用于插件扫描队列界面的显示
        String messageLevel = this.yamlReader.getString("messageLevel");

        // 判断是否开启插件
        if (!this.tags.getBaseSettingTagClass().isStart()) {
            return null;
        }

        // 判断域名黑名单
        if (domainNameBlacklist != null && domainNameBlacklist.size() >= 1) {
            if (isMatchDomainName(baseBurpUrl.getRequestHost(), domainNameBlacklist)) {
                return null;
            }
        }

        // 判断域名白名单
        if (domainNameWhitelist != null && domainNameWhitelist.size() >= 1) {
            if (!isMatchDomainName(baseBurpUrl.getRequestHost(), domainNameWhitelist)) {
                return null;
            }
        }

        // 判断当前请求后缀,是否为url黑名单后缀
        if (this.isUrlBlackListSuffix(baseBurpUrl)) {
            return null;
        }

        // 判断当前站点是否超出扫描数量了
        Integer siteScanNumber = this.yamlReader.getInteger("scan.siteScanNumber");
        if (siteScanNumber != 0) {
            Integer siteNumber = this.getSiteNumber(baseBurpUrl.getRequestDomainName());
            if (siteNumber >= siteScanNumber) {
                if (messageLevel.equals("ALL")) {
                    this.tags.getScanQueueTagClass().add(
                            "",
                            "",
                            this.helpers.analyzeRequest(baseRequestResponse).getMethod(),
                            baseBurpUrl.getHttpRequestUrl().toString(),
                            this.helpers.analyzeResponse(baseRequestResponse.getResponse()).getStatusCode() + "",
                            "the number of website scans exceeded",
                            baseRequestResponse
                    );
                }
                return null;
            }
        }

        // 判断当前站点的shiro指纹问题数量是否超出了
        Integer shiroFingerprintScanIssueNumber = this.yamlReader.getInteger("application.shiroFingerprintExtension.config.issueNumber");
        if (shiroFingerprintScanIssueNumber != 0) {
            String shiroFingerprintIssueName = this.yamlReader.getString("application.shiroFingerprintExtension.config.issueName");
            Integer shiroFingerprintIssueNumber = this.getSiteIssueNumber(baseBurpUrl.getRequestDomainName(), shiroFingerprintIssueName);
            if (shiroFingerprintIssueNumber >= shiroFingerprintScanIssueNumber) {
                if (messageLevel.equals("ALL")) {
                    this.tags.getScanQueueTagClass().add(
                            "",
                            "",
                            this.helpers.analyzeRequest(baseRequestResponse).getMethod(),
                            baseBurpUrl.getHttpRequestUrl().toString(),
                            this.helpers.analyzeResponse(baseRequestResponse.getResponse()).getStatusCode() + "",
                            "shiro fingerprint problems have exceeded the number",
                            baseRequestResponse
                    );
                }
                return null;
            }
        }

        // 判断当前站点的shiro加密key问题数量是否超出了
        Integer shiroCipherKeyScanIssueNumber = this.yamlReader.getInteger("application.shiroCipherKeyExtension.config.issueNumber");
        if (shiroCipherKeyScanIssueNumber != 0) {
            String shiroCipherKeyIssueName = this.yamlReader.getString("application.shiroCipherKeyExtension.config.issueName");
            Integer shiroCipherKeyIssueNumber = this.getSiteIssueNumber(baseBurpUrl.getRequestDomainName(), shiroCipherKeyIssueName);
            if (shiroCipherKeyIssueNumber >= shiroCipherKeyScanIssueNumber) {
                if (messageLevel.equals("ALL")) {
                    this.tags.getScanQueueTagClass().add(
                            "",
                            "",
                            this.helpers.analyzeRequest(baseRequestResponse).getMethod(),
                            baseBurpUrl.getHttpRequestUrl().toString(),
                            this.helpers.analyzeResponse(baseRequestResponse.getResponse()).getStatusCode() + "",
                            "shiro encryption key leakage problems have exceeded the number",
                            baseRequestResponse
                    );
                }
                return null;
            }
        }

        // shiro指纹探测扩展
        ShiroFingerprint shiroFingerprint = new ShiroFingerprint(this.callbacks, this.yamlReader, baseRequestResponse);

        // 判断指纹模块是否正常
        if (!shiroFingerprint.run().isRunExtension()) {
            this.tags.getScanQueueTagClass().add(
                    "",
                    "",
                    this.helpers.analyzeRequest(baseRequestResponse).getMethod(),
                    baseBurpUrl.getHttpRequestUrl().toString(),
                    this.helpers.analyzeResponse(baseRequestResponse.getResponse()).getStatusCode() + "",
                    "shiro fingerprint module startup error",
                    baseRequestResponse
            );
            return null;
        }

        // 检测是否shiro框架
        if (!shiroFingerprint.run().isShiroFingerprint()) {
            if (messageLevel.equals("ALL")) {
                this.tags.getScanQueueTagClass().add(
                        "",
                        "",
                        this.helpers.analyzeRequest(baseRequestResponse).getMethod(),
                        baseBurpUrl.getHttpRequestUrl().toString(),
                        this.helpers.analyzeResponse(baseRequestResponse.getResponse()).getStatusCode() + "",
                        "the site is not a shiro framework",
                        baseRequestResponse
                );
            }
            return null;
        }

        // shiro指纹检测-控制台报告输出
        shiroFingerprint.run().consoleExport();

        // shiro指纹检测-报告输出
        issues.add(shiroFingerprint.run().export());

        // 添加任务到面板中等待检测
        int tagId = this.tags.getScanQueueTagClass().add(
                "",
                "",
                this.helpers.analyzeRequest(baseRequestResponse).getMethod(),
                baseBurpUrl.getHttpRequestUrl().toString(),
                this.helpers.analyzeResponse(baseRequestResponse.getResponse()).getStatusCode() + "",
                "waiting for test results",
                baseRequestResponse
        );

        try {
            // shiro加密key扩展
            Boolean isStartShiroCipherKeyExtension = this.yamlReader.getBoolean("application.shiroCipherKeyExtension.config.isStart");
            Boolean isScanCbcEncrypt = this.yamlReader.getBoolean("application.shiroCipherKeyExtension.config.isScanCbcEncrypt");
            Boolean isScanGcmEncrypt = this.yamlReader.getBoolean("application.shiroCipherKeyExtension.config.isScanGcmEncrypt");
            if (isStartShiroCipherKeyExtension && (isScanCbcEncrypt || isScanGcmEncrypt)) {
                // 启动线程跑shiro加密key扩展任务
                String callClassName = this.yamlReader.getString("application.shiroCipherKeyExtension.config.provider");
                ShiroCipherKeyThread shiroCipherKeyThread = new ShiroCipherKeyThread(
                        this.globalVariableReader,
                        globalPassiveScanVariableReader,
                        this.callbacks,
                        this.yamlReader,
                        baseRequestResponse,
                        shiroFingerprint,
                        callClassName);

                // 监控线程
                while (true) {
                    if (shiroCipherKeyThread.isTaskComplete()) {
                        break;
                    }

                    // 单纯的等待～
                    Thread.sleep(500);
                }

                // 尝试获取shiro加密key扩展的数据
                // 注意: 只有成功爆破出shiro加密key了才会有数据
                IShiroCipherKeyExtension shiroCipherKey = globalPassiveScanVariableReader.getShiroCipherKeyExtensionData("shiroCipherKey");

                // 为空的时候,表示没有成功爆破出shiro加密key
                if (shiroCipherKey == null) {
                    // 未检查出来key-更新任务状态至任务栏面板
                    this.tags.getScanQueueTagClass().save(
                            tagId,
                            "",
                            "",
                            this.helpers.analyzeRequest(baseRequestResponse).getMethod(),
                            baseBurpUrl.getHttpRequestUrl().toString(),
                            this.helpers.analyzeResponse(baseRequestResponse.getResponse()).getStatusCode() + "",
                            "[-] not found shiro key",
                            baseRequestResponse);
                    return issues;
                }

                // 检查出来key-更新任务状态至任务栏面板
                IHttpRequestResponse shiroCipherKeyRequestResponse = shiroCipherKey.getHttpRequestResponse();
                this.tags.getScanQueueTagClass().save(
                        tagId,
                        shiroCipherKey.getExtensionName(),
                        shiroCipherKey.getEncryptMethod(),
                        this.helpers.analyzeRequest(shiroCipherKeyRequestResponse).getMethod(),
                        baseBurpUrl.getHttpRequestUrl().toString(),
                        this.helpers.analyzeResponse(shiroCipherKeyRequestResponse.getResponse()).getStatusCode() + "",
                        "[+] found shiro key:" + shiroCipherKey.getCipherKey(),
                        shiroCipherKeyRequestResponse);

                // shiro加密key-控制台报告输出
                shiroCipherKey.consoleExport();

                // shiro加密key-报告输出
                issues.add(shiroCipherKey.export());
            } else {
                this.tags.getScanQueueTagClass().save(
                        tagId,
                        "",
                        "",
                        this.helpers.analyzeRequest(shiroFingerprint.run().getHttpRequestResponse()).getMethod(),
                        baseBurpUrl.getHttpRequestUrl().toString(),
                        this.helpers.analyzeResponse(shiroFingerprint.run().getHttpRequestResponse().getResponse()).getStatusCode() + "",
                        "[*] shiro fingerprint",
                        shiroFingerprint.run().getHttpRequestResponse());
            }

            URL httpRequestUrl = baseBurpUrl.getHttpRequestUrl();
            this.stdout.println("============shiro-key扫描完毕================");
            this.stdout.println(String.format("url: %s", httpRequestUrl));
            this.stdout.println("========================================");
        } catch (Exception e) {
            // 判断是否有shiro指纹,输出到问题面板过
            // 如果有,那么爆致命错误的时候就可以删除issues变量的数据
            // 防止因为因为跑key一直错误,间接导致站点指纹数量满了
            String shiroFingerprintIssueName = this.yamlReader.getString("application.shiroFingerprintExtension.config.issueName");
            Integer shiroFingerprintIssueNumber = this.getSiteIssueNumber(baseBurpUrl.getRequestDomainName(), shiroFingerprintIssueName);
            if (shiroFingerprintIssueNumber >= 1 && issues.size() >= 1) {
                issues.remove(0);
            }

            this.stdout.println("========插件错误-未知错误============");
            this.stdout.println(String.format("url: %s", baseBurpUrl.getHttpRequestUrl().toString()));
            this.stdout.println("请使用该url重新访问,若是还多次出现此错误,则很有可能waf拦截");
            this.stdout.println("错误详情请查看Extender里面对应插件的Errors标签页");
            this.stdout.println("========================================");
            this.stdout.println(" ");

            this.tags.getScanQueueTagClass().save(
                    tagId,
                    "",
                    "",
                    this.helpers.analyzeRequest(baseRequestResponse).getMethod(),
                    baseBurpUrl.getHttpRequestUrl().toString(),
                    this.helpers.analyzeResponse(baseRequestResponse.getResponse()).getStatusCode() + "",
                    "[x] unknown error",
                    baseRequestResponse);

            e.printStackTrace(this.stderr);
        }

        return issues;
    }

    @Override
    public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
        return null;
    }

    @Override
    public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue) {
        return 0;
    }

    @Override
    public void extensionUnloaded() {
        this.globalVariableReader.putBooleanData("isExtensionUnload", true);
    }

    /**
     * 判断是否查找的到指定的域名
     *
     * @param domainName     需匹配的域名
     * @param domainNameList 待匹配的域名列表
     * @return
     */
    private static Boolean isMatchDomainName(String domainName, List<String> domainNameList) {
        domainName = domainName.trim();

        if (domainName.length() <= 0) {
            return false;
        }

        if (domainNameList == null || domainNameList.size() <= 0) {
            return false;
        }

        if (domainName.contains(":")) {
            domainName = domainName.substring(0, domainName.indexOf(":"));
        }

        String reverseDomainName = new StringBuffer(domainName).reverse().toString();

        for (String domainName2 : domainNameList) {
            domainName2 = domainName2.trim();

            if (domainName2.length() <= 0) {
                continue;
            }

            if (domainName2.contains(":")) {
                domainName2 = domainName2.substring(0, domainName2.indexOf(":"));
            }

            String reverseDomainName2 = new StringBuffer(domainName2).reverse().toString();

            if (domainName.equals(domainName2)) {
                return true;
            }

            if (reverseDomainName.contains(".") && reverseDomainName2.contains(".")) {
                List<String> splitDomainName = new ArrayList<String>(Arrays.asList(reverseDomainName.split("[.]")));

                List<String> splitDomainName2 = new ArrayList<String>(Arrays.asList(reverseDomainName2.split("[.]")));

                if (splitDomainName.size() <= 0 || splitDomainName2.size() <= 0) {
                    continue;
                }

                if (splitDomainName.size() < splitDomainName2.size()) {
                    for (int i = splitDomainName.size(); i < splitDomainName2.size(); i++) {
                        splitDomainName.add("*");
                    }
                }

                if (splitDomainName.size() > splitDomainName2.size()) {
                    for (int i = splitDomainName2.size(); i < splitDomainName.size(); i++) {
                        splitDomainName2.add("*");
                    }
                }

                int ii = 0;
                for (int i = 0; i < splitDomainName.size(); i++) {
                    if (splitDomainName2.get(i).equals("*")) {
                        ii = ii + 1;
                    } else if (splitDomainName.get(i).equals(splitDomainName2.get(i))) {
                        ii = ii + 1;
                    }
                }

                if (ii == splitDomainName.size()) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * 判断是否url黑名单后缀
     * 大小写不区分
     * 是 = true, 否 = false
     *
     * @param burpUrl
     * @return
     */
    private boolean isUrlBlackListSuffix(CustomBurpUrl burpUrl) {
        if (!this.yamlReader.getBoolean("urlBlackListSuffix.config.isStart")) {
            return false;
        }

        String noParameterUrl = burpUrl.getHttpRequestUrl().toString().split("\\?")[0];
        String urlSuffix = noParameterUrl.substring(noParameterUrl.lastIndexOf(".") + 1);

        List<String> suffixList = this.yamlReader.getStringList("urlBlackListSuffix.suffixList");
        if (suffixList == null || suffixList.size() == 0) {
            return false;
        }

        for (String s : suffixList) {
            if (s.toLowerCase().equals(urlSuffix.toLowerCase())) {
                return true;
            }
        }

        return false;
    }

    /**
     * 网站问题数量
     *
     * @param domainName 请求域名名称
     * @param issueName  要查询的问题名称
     * @return
     */
    private Integer getSiteIssueNumber(String domainName, String issueName) {
        Integer number = 0;

        for (IScanIssue Issue : this.callbacks.getScanIssues(domainName)) {
            if (Issue.getIssueName().equals(issueName)) {
                number++;
            }
        }

        return number;
    }

    /**
     * 站点出现数量
     *
     * @param domainName
     * @return
     */
    private Integer getSiteNumber(String domainName) {
        Integer number = 0;
        for (IHttpRequestResponse requestResponse : this.callbacks.getSiteMap(domainName)) {
            number++;
        }
        return number;
    }
}
