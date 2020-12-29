package burp.Bootstrap;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class DomainNameRepeat {

    private Map<String, Integer> domainNameMap;

    public DomainNameRepeat() {
        this.domainNameMap = new ConcurrentHashMap<String, Integer>();
    }

    public Map<String, Integer> getDomainNameMap() {
        return this.domainNameMap;
    }

    public void add(String domainName) {
        if (domainName == null || domainName.length() <= 0) {
            throw new IllegalArgumentException("域名不能为空");
        }

        synchronized (this.getDomainNameMap()) {
            this.getDomainNameMap().put(domainName, 1);
        }
    }

    public void del(String domainName) {
        if (this.getDomainNameMap().get(domainName) != null) {
            this.getDomainNameMap().remove(domainName);
        }
    }

    /**
     * 重复主机的检测
     * true  表示重复
     * false 表示不重复
     * @param domainName
     * @return boolean
     */
    public boolean check(String domainName) {
        if (this.getDomainNameMap().get(domainName) != null) {
            return true;
        }
        return false;
    }
}
