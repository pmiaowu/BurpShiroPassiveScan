package burp.Application.ShiroCipherKeyExtension;

import java.util.Date;
import java.util.List;
import java.io.PrintWriter;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;

import burp.Bootstrap.GlobalPassiveScanVariableReader;
import burp.IHttpRequestResponse;
import burp.IBurpExtenderCallbacks;

import burp.Bootstrap.YamlReader;
import burp.Bootstrap.GlobalVariableReader;
import burp.Bootstrap.Encrypt.CbcEncrypt;
import burp.Bootstrap.Encrypt.GcmEncrypt;
import burp.Bootstrap.Encrypt.EncryptInterface;

import burp.Application.ShiroFingerprintExtension.ShiroFingerprint;

import burp.Application.ShiroCipherKeyExtension.ExtensionInterface.IShiroCipherKeyExtension;

public class ShiroCipherKey implements Runnable {
    private GlobalVariableReader globalVariableReader;
    private GlobalPassiveScanVariableReader globalPassiveScanVariableReader;

    private IBurpExtenderCallbacks callbacks;

    private YamlReader yamlReader;

    private IHttpRequestResponse baseRequestResponse;

    private ShiroFingerprint shiroFingerprint;

    private String callClassName;

    private List<String> payloadList;

    /**
     * 该模块启动日期
     */
    private final Date startDate = new Date();

    /**
     * 程序最大执行时间,单位为秒
     * 注意: 会根据payload的添加而添加
     */
    private final int maxExecutionTime = 60;

    public ShiroCipherKey(GlobalVariableReader globalVariableReader,
                          GlobalPassiveScanVariableReader globalPassiveScanVariableReader,
                          IBurpExtenderCallbacks callbacks,
                          YamlReader yamlReader,
                          IHttpRequestResponse baseRequestResponse,
                          ShiroFingerprint shiroFingerprint,
                          String callClassName,
                          List<String> payloadList) {
        this.globalVariableReader = globalVariableReader;
        this.globalPassiveScanVariableReader = globalPassiveScanVariableReader;

        this.callbacks = callbacks;

        this.yamlReader = yamlReader;

        this.baseRequestResponse = baseRequestResponse;

        this.shiroFingerprint = shiroFingerprint;

        this.callClassName = callClassName;

        this.payloadList = payloadList;
    }

    @Override
    public void run() {
        if (callClassName == null || callClassName.length() <= 0) {
            throw new IllegalArgumentException("Application.ShiroCipherKeyExtension-请输入要调用的插件名称");
        }

        if (this.payloadList.size() == 0) {
            throw new IllegalArgumentException("Application.ShiroCipherKeyExtension-获取的payloads为空,无法正常运行");
        }

        try {
            Class c = Class.forName("burp.Application.ShiroCipherKeyExtension.ExtensionMethod." + callClassName);
            Constructor cConstructor = c.getConstructor(
                    GlobalVariableReader.class,
                    GlobalPassiveScanVariableReader.class,
                    IBurpExtenderCallbacks.class,
                    YamlReader.class,
                    IHttpRequestResponse.class,
                    ShiroFingerprint.class,
                    List.class,
                    EncryptInterface.class,
                    Date.class,
                    Integer.class);

            Boolean isScanCbcEncrypt = this.yamlReader.getBoolean("application.shiroCipherKeyExtension.config.isScanCbcEncrypt");
            if (isScanCbcEncrypt) {
                if (this.globalPassiveScanVariableReader.getBooleanData("isEndShiroCipherKeyTask")) {
                    return;
                }

                IShiroCipherKeyExtension shiroCipherKey1 = (IShiroCipherKeyExtension) cConstructor.newInstance(
                        this.globalVariableReader,
                        this.globalPassiveScanVariableReader,
                        this.callbacks,
                        this.yamlReader,
                        this.baseRequestResponse,
                        this.shiroFingerprint,
                        this.payloadList,
                        new CbcEncrypt(),
                        this.startDate,
                        this.getMaxExecutionTime());

                if (shiroCipherKey1.isShiroCipherKeyExists()) {
                    this.globalPassiveScanVariableReader.putBooleanData("isEndShiroCipherKeyTask", true);
                    this.globalPassiveScanVariableReader.putShiroCipherKeyExtensionData("shiroCipherKey", shiroCipherKey1);
                }
            }

            Boolean isScanGcmEncrypt = this.yamlReader.getBoolean("application.shiroCipherKeyExtension.config.isScanGcmEncrypt");
            if (isScanGcmEncrypt) {
                if (this.globalPassiveScanVariableReader.getBooleanData("isEndShiroCipherKeyTask")) {
                    return;
                }

                IShiroCipherKeyExtension shiroCipherKey2 = (IShiroCipherKeyExtension) cConstructor.newInstance(
                        this.globalVariableReader,
                        this.globalPassiveScanVariableReader,
                        this.callbacks,
                        this.yamlReader,
                        this.baseRequestResponse,
                        this.shiroFingerprint,
                        this.payloadList,
                        new GcmEncrypt(),
                        this.startDate,
                        this.getMaxExecutionTime());

                if (shiroCipherKey2.isShiroCipherKeyExists()) {
                    this.globalPassiveScanVariableReader.putBooleanData("isEndShiroCipherKeyTask", true);
                    this.globalPassiveScanVariableReader.putShiroCipherKeyExtensionData("shiroCipherKey", shiroCipherKey2);
                }
            }
        } catch (ClassNotFoundException | NoSuchMethodException | InstantiationException | IllegalAccessException | InvocationTargetException e) {
            e.printStackTrace(new PrintWriter(this.callbacks.getStderr(), true));
        }
    }

    /**
     * 程序最大执行时间,单位为秒
     * 会根据payload的添加而添加
     *
     * @return
     */
    private Integer getMaxExecutionTime() {
        Integer maxExecutionTime = this.maxExecutionTime;
        maxExecutionTime += this.payloadList.size() * 6;
        return maxExecutionTime;
    }
}