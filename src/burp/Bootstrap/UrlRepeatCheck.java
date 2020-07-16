package burp.Bootstrap;

import java.util.List;
import java.util.ArrayList;

import java.net.URL;
import java.net.MalformedURLException;

public class UrlRepeatCheck {
    private List<String> requestMethodList;
    private List<String> urlList;

    public UrlRepeatCheck() {
        this.requestMethodList = new ArrayList<String>();
        this.urlList = new ArrayList<String>();
    }

    public List<String> getRequestMethodList() {
        return this.requestMethodList;
    }

    public List<String> getUrlList() {
        return this.urlList;
    }

    public void addMethodAndUrl(String requestMethod, String url) {
        if (requestMethod == null || requestMethod.length() <= 0) {
            throw new IllegalArgumentException("请求方法不能为空");
        }

        if (url == null || url.length() <= 0) {
            throw new IllegalArgumentException("url不能为空");
        }

        this.requestMethodList.add(requestMethod);
        this.urlList.add(url);
    }

    /**
     * 重复url的检测
     * true  表示重复
     * false 表示不重复
     * @param url
     * @return boolean
     */
    public boolean isUrlRepeat(String requestMethod, String url) {
        for (int i = 0; i < this.getUrlList().size(); i++) {
            if (!this.getUrlList().get(i).equals(url)) {
                continue;
            }
            if (this.getRequestMethodList().get(i).equals(requestMethod)) {
                return true;
            }
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
