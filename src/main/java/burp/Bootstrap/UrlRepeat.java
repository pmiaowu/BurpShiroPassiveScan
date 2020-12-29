package burp.Bootstrap;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class UrlRepeat {
    private Map<String, Integer> requestMethodAndUrlMap;

    public UrlRepeat() {
        this.requestMethodAndUrlMap = new ConcurrentHashMap<String, Integer>();
    }

    public Map<String, Integer> getRequestMethodAndUrlMap() {
        return this.requestMethodAndUrlMap;
    }

    public void addMethodAndUrl(String requestMethod, String url) {
        if (requestMethod == null || requestMethod.length() <= 0) {
            throw new IllegalArgumentException("请求方法不能为空");
        }

        if (url == null || url.length() <= 0) {
            throw new IllegalArgumentException("url不能为空");
        }

        synchronized (this.getRequestMethodAndUrlMap()) {
            this.getRequestMethodAndUrlMap().put(requestMethod + " " + url, 1);
        }
    }

    public void delMethodAndUrl(String requestMethod, String url) {
        if (requestMethod == null || requestMethod.length() <= 0) {
            return;
        }

        if (url == null || url.length() <= 0) {
            return;
        }

        this.getRequestMethodAndUrlMap().remove(requestMethod + " " + url);
    }

    /**
     * 重复url的检测
     * true  表示重复
     * false 表示不重复
     * @param url
     * @return boolean
     */
    public boolean check(String requestMethod, String url) {
        if (this.getRequestMethodAndUrlMap().get(requestMethod + " " + url) != null) {
            return true;
        }
        return false;
    }

    /**
     * 删除url参数值
     * @param url
     * @return String
     */
    public String RemoveUrlParameterValue(String url) {
        try {
            String newUrl = "";
            URL url1 = new URL(url);
            String urlQuery = url1.getQuery();

            if (urlQuery == null) {
                return url;
            }

            String noParameterUrl = url.replace(urlQuery, "");
            newUrl = noParameterUrl + this.RemoveParameterValue(urlQuery);
            return newUrl;
        } catch (MalformedURLException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * 删除参数值
     * @param urlQuery
     * @return String
     */
    private String RemoveParameterValue(String urlQuery) {
        String parameter = "";
        for (String query : urlQuery.split("&")) {
            String[] parameterList = query.split("=");
            parameter += parameterList[0] + "=&";
        }
        parameter = parameter.substring(0,parameter.length() - 1);
        return parameter;
    }
}
