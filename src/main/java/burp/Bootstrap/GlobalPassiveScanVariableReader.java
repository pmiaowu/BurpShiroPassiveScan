package burp.Bootstrap;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import burp.Application.ShiroCipherKeyExtension.ExtensionInterface.IShiroCipherKeyExtension;

/**
 * 专门拿来做被动扫描器变量共享的类
 */
public class GlobalPassiveScanVariableReader {
    private ConcurrentHashMap booleanMap;
    private ConcurrentHashMap shiroCipherKeyExtensioMap;

    public GlobalPassiveScanVariableReader() {
        this.booleanMap = new ConcurrentHashMap<String, Boolean>();
        this.shiroCipherKeyExtensioMap = new ConcurrentHashMap<String, IShiroCipherKeyExtension>();
    }

    public Map<String, Boolean> getBooleanMap() {
        return this.booleanMap;
    }

    public Boolean getBooleanData(String key) {
        return this.getBooleanMap().get(key);
    }

    public void putBooleanData(String key, Boolean b) {
        if (key == null || key.length() <= 0) {
            throw new IllegalArgumentException("key不能为空");
        }

        synchronized (this.getBooleanMap()) {
            this.getBooleanMap().put(key, b);
        }
    }

    public void delBooleanData(String key) {
        if (this.getBooleanMap().get(key) != null) {
            this.getBooleanMap().remove(key);
        }
    }

    public Map<String, IShiroCipherKeyExtension> getShiroCipherKeyExtensioMap() {
        return this.shiroCipherKeyExtensioMap;
    }

    public IShiroCipherKeyExtension getShiroCipherKeyExtensionData(String key) {
        return this.getShiroCipherKeyExtensioMap().get(key);
    }

    public void putShiroCipherKeyExtensionData(String key, IShiroCipherKeyExtension b) {
        if (key == null || key.length() <= 0) {
            throw new IllegalArgumentException("key不能为空");
        }

        synchronized (this.getShiroCipherKeyExtensioMap()) {
            this.getShiroCipherKeyExtensioMap().put(key, b);
        }
    }

    public void delShiroCipherKeyExtensionData(String key) {
        if (this.getShiroCipherKeyExtensioMap().get(key) != null) {
            this.getShiroCipherKeyExtensioMap().remove(key);
        }
    }
}
