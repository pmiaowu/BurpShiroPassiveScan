package burp.Bootstrap;

import java.util.List;
import java.util.ArrayList;

public class DomainNameRepeat {

    private List<String> domainNameList;

    public DomainNameRepeat() {
        this.domainNameList = new ArrayList<String>();
    }

    public List<String> getDomainNameList() {
        return this.domainNameList;
    }

    /**
     * 重复主机的检测
     * true  表示重复
     * false 表示不重复
     * @param host
     * @return boolean
     */
    public boolean check(String host) {
        for (int i = 0; i < this.getDomainNameList().size(); i++) {
            if (this.getDomainNameList().get(i).equals(host)) {
                return true;
            }
        }
        return false;
    }
}
