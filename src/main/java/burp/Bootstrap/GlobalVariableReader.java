package burp.Bootstrap;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 专门拿来做插件的全局变量共享的类
 */
public class GlobalVariableReader {
    private ConcurrentHashMap booleanMap;

    public GlobalVariableReader() {
        this.booleanMap = new ConcurrentHashMap<String, Boolean>();
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
}