package burp.Bootstrap;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class DiffPage {
    /**
     * 返回经过过滤无用的数据以后两个字符串的相似度
     * @param str
     * @param target
     * @return
     */
    public static double getRatio(String str, String target) {
        str = getFilteredPageContent(str);
        target = getFilteredPageContent(target);
        return getSimilarityRatio(str, target);
    }

    /**
     * 返回经过过滤的页面内容，不包含脚本、样式和/或注释
     * 或所有HTML标签
     * 调用 getFilteredPageContent("<html><title>foobar</title></style><body>test</body></html>")
     * 返回内容: foobar test
     * @param inputString
     * @return textStr;
     */
    public static String getFilteredPageContent(String inputString) {
        if (inputString == null)
            return null;
        inputString = inputString.trim();
        String htmlStr = inputString; // 含html标签的字符串
        String textStr = "";

        try {
            //定义script的正则表达式{或<script[^>]*?>[\\s\\S]*?<\\/script>
            String regEx_script = "<[\\s]*?script[^>]*?>[\\s\\S]*?<[\\s]*?\\/[\\s]*?script[\\s]*?>";

            //定义style的正则表达式{或<style[^>]*?>[\\s\\S]*?<\\/style>
            String regEx_style = "<[\\s]*?style[^>]*?>[\\s\\S]*?<[\\s]*?\\/[\\s]*?style[\\s]*?>";

            // 定义HTML标签的正则表达式
            String regEx_html = "<[^>]+>";

            // 定义一些特殊字符的正则表达式 如：&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
            String regEx_special = "\\&[a-zA-Z]{1,10};";

            // 过滤script标签
            Pattern p_script = Pattern.compile(regEx_script, Pattern.CASE_INSENSITIVE);
            Matcher m_script = p_script.matcher(htmlStr);
            htmlStr = m_script.replaceAll("");

            // 过滤style标签
            Pattern p_style = Pattern.compile(regEx_style, Pattern.CASE_INSENSITIVE);
            Matcher m_style = p_style.matcher(htmlStr);
            htmlStr = m_style.replaceAll("");

            // 过滤html标签
            Pattern p_html = Pattern.compile(regEx_html, Pattern.CASE_INSENSITIVE);
            Matcher m_html = p_html.matcher(htmlStr);
            htmlStr = m_html.replaceAll("");

            // 将实体字符串转义返回 如: "&lt;"="<", "&gt;"=">", "&quot;"="\"", "&nbsp;"=" ", "&amp;"="&"
            htmlStr = htmlStr.replace("&lt;", "<");
            htmlStr = htmlStr.replace("&gt;", ">");
            htmlStr = htmlStr.replace("&quot;", "\"");
            htmlStr = htmlStr.replace("&nbsp;", " ");
            htmlStr = htmlStr.replace("&amp;", "&");

            // 过滤特殊标签
            Pattern p_special = Pattern.compile(regEx_special, Pattern.CASE_INSENSITIVE);
            Matcher m_special = p_special.matcher(htmlStr);
            htmlStr = m_special.replaceAll("");

            textStr = htmlStr;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        return textStr;// 返回文本字符串
    }

    /**
     * 两个字符串相似度匹配
     * @param str
     * @param target
     * @return double
     */
    public static double getSimilarityRatio(String str, String target) {
        if (str.equals(target)) {
            return 1;
        }

        int d[][]; // 矩阵
        int n = str.length();
        int m = target.length();
        int i; // 遍历str的
        int j; // 遍历target的
        char ch1; // str的
        char ch2; // target的
        int temp; // 记录相同字符,在某个矩阵位置值的增量,不是0就是1
        if (n == 0 || m == 0) {
            return 0;
        }

        d = new int[n + 1][m + 1];
        for (i = 0; i <= n; i++) { // 初始化第一列
            d[i][0] = i;
        }

        for (j = 0; j <= m; j++) { // 初始化第一行
            d[0][j] = j;
        }

        for (i = 1; i <= n; i++) { // 遍历str
            ch1 = str.charAt(i - 1);
            // 去匹配target
            for (j = 1; j <= m; j++) {
                ch2 = target.charAt(j - 1);
                if (ch1 == ch2 || ch1 == ch2 + 32 || ch1 + 32 == ch2) {
                    temp = 0;
                } else {
                    temp = 1;
                }
                // 左边+1,上边+1, 左上角+temp取最小
                d[i][j] = Math.min(Math.min(d[i - 1][j] + 1, d[i][j - 1] + 1), d[i - 1][j - 1] + temp);
            }
        }

        return (1 - (double) d[n][m] / Math.max(str.length(), target.length()));
    }
}
