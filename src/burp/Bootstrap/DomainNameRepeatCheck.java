package burp.Bootstrap;

import java.util.List;
import java.util.ArrayList;

public class DomainNameRepeatCheck {

    private List<String> domainNameList;

    public DomainNameRepeatCheck() {
        this.domainNameList = new ArrayList<String>();
    }

    public List<String> getDomainNameList() {
        return this.domainNameList;
    }

    /*
     * 重复主机的检测
     * true  表示重复
     * false 表示不重复
     * */
    public boolean isDomainNameRepeat(String host) {
        for (int i = 0; i < this.getDomainNameList().size(); i++) {
            if (this.getDomainNameList().get(i).equals(host)) {
                return true;
            }
        }
        return false;
    }
}
