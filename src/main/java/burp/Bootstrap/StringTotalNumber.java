package burp.Bootstrap;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class StringTotalNumber {

    private ConcurrentHashMap stringMap;

    public StringTotalNumber() {
        this.stringMap = new ConcurrentHashMap<String, Integer>();
    }

    public Map<String, Integer> getStringMap() {
        return this.stringMap;
    }

    public Integer getData(String key) {
        return this.getStringMap().get(key);
    }

    public void add(String key) {
        if (key == null || key.length() <= 0) {
            throw new IllegalArgumentException("查询的key不能为空");
        }

        synchronized (this.getStringMap()) {
            if (this.getData(key) == null) {
                this.getStringMap().put(key, 1);
            } else {
                this.getStringMap().put(key, (this.getData(key) + 1));
            }
        }
    }

    public void del(String key) {
        if (this.getStringMap().get(key) != null) {
            this.getStringMap().remove(key);
        }
    }
}
