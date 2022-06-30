package burp.Application.ShiroCipherKeyExtension;

import java.util.List;
import java.util.ArrayList;

import burp.IHttpRequestResponse;
import burp.IBurpExtenderCallbacks;

import burp.Bootstrap.YamlReader;
import burp.Bootstrap.CustomHelpers;
import burp.Bootstrap.GlobalVariableReader;
import burp.Bootstrap.GlobalPassiveScanVariableReader;

import burp.Application.ShiroFingerprintExtension.ShiroFingerprint;

public class ShiroCipherKeyThread {
    private List<Thread> threadPool = new ArrayList<>();

    public ShiroCipherKeyThread(GlobalVariableReader globalVariableReader,
                                GlobalPassiveScanVariableReader globalPassiveScanVariableReader,
                                IBurpExtenderCallbacks callbacks,
                                YamlReader yamlReader,
                                IHttpRequestResponse baseRequestResponse,
                                ShiroFingerprint shiroFingerprint,
                                String callClassName) {
        // 是否结束shiro加密key扩展任务
        // 用于多线程,跑到key,把程序快速退出去,避免资源浪费与卡顿
        // true = 结束, false = 不结束
        globalPassiveScanVariableReader.putBooleanData("isEndShiroCipherKeyTask", false);

        if (callClassName == null || callClassName.length() <= 0) {
            throw new IllegalArgumentException("Application.ShiroCipherKeyExtension-请输入要调用的插件名称");
        }

        List<String> payloads = yamlReader.getStringList("application.shiroCipherKeyExtension.config.payloads");
        if (payloads.size() == 0) {
            throw new IllegalArgumentException("Application.ShiroCipherKeyExtension-获取的payloads为空,无法正常运行");
        }

        // payload按照配置线程数分块
        Integer shiroCipherKeyThreadTotal = yamlReader.getInteger("application.shiroCipherKeyExtension.config.threadTotal");
        List<List<String>> payloadChunk = CustomHelpers.listChunkSplit(payloads, shiroCipherKeyThreadTotal);

        // 建立线程池
        for (List<String> payloadList : payloadChunk) {
            this.threadPool.add(new Thread(
                    new ShiroCipherKey(
                            globalVariableReader, globalPassiveScanVariableReader, callbacks,
                            yamlReader, baseRequestResponse, shiroFingerprint,
                            callClassName, payloadList)
            ));
        }

        // 线程启动
        for (int i = 0; i < this.threadPool.size(); i++) {
            this.threadPool.get(i).start();
        }
    }

    /**
     * 判断线程任务是否执行完毕
     *
     * @return
     */
    public Boolean isTaskComplete() {
        // 开启的线程总数
        Integer threadCcount = this.threadPool.size();

        // 线程完成数量
        Integer threadNum = 0;

        for (Thread t : this.threadPool) {
            if (!t.isAlive()) {
                threadNum++;
            }
        }

        if (threadNum.equals(threadCcount)) {
            return true;
        }

        return false;
    }
}
