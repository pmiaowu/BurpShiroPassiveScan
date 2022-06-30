package burp.Ui;

import java.awt.*;
import javax.swing.JTabbedPane;

import burp.ITab;
import burp.IBurpExtenderCallbacks;

import burp.Bootstrap.YamlReader;

public class Tags implements ITab {
    private final JTabbedPane tabs;

    private String tagName;

    private BaseSettingTag baseSettingTag;
    private ScanQueueTag scanQueueTag;

    public Tags(IBurpExtenderCallbacks callbacks, String name) {
        this.tagName = name;

        tabs = new JTabbedPane();

        YamlReader yamlReader = YamlReader.getInstance(callbacks);

        // 扫描队列-窗口
        ScanQueueTag scanQueueTag = new ScanQueueTag(callbacks, tabs);
        this.scanQueueTag = scanQueueTag;

        // 基本设置-窗口
        BaseSettingTag baseSettingTag = new BaseSettingTag(callbacks, tabs, yamlReader);
        this.baseSettingTag = baseSettingTag;

        // 自定义组件-导入
        callbacks.customizeUiComponent(tabs);

        // 将自定义选项卡添加到Burp的UI
        callbacks.addSuiteTab(Tags.this);
    }

    /**
     * 基础设置tag
     *
     * @return
     */
    public BaseSettingTag getBaseSettingTagClass() {
        return this.baseSettingTag;
    }

    /**
     * 扫描队列tag
     * 可通过该类提供的方法,进行tag任务的添加与修改
     *
     * @return
     */
    public ScanQueueTag getScanQueueTagClass() {
        return this.scanQueueTag;
    }

    @Override
    public String getTabCaption() {
        return this.tagName;
    }

    @Override
    public Component getUiComponent() {
        return this.tabs;
    }
}