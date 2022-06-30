package burp.Bootstrap;

public class DiffPage {
    /**
     * 返回经过过滤无用的数据以后两个字符串的相似度
     *
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
     * 返回内容: foobartest
     *
     * @param htmlStr
     * @return String
     */
    public static String getFilteredPageContent(String htmlStr) {
        // 将实体字符串转义返回 如: "&lt;"="<", "&gt;"=">", "&quot;"="\"", "&nbsp;"=" ", "&amp;"="&"
        htmlStr = htmlStr.replace("&lt;", "<");
        htmlStr = htmlStr.replace("&gt;", ">");
        htmlStr = htmlStr.replace("&quot;", "\"");
        htmlStr = htmlStr.replace("&nbsp;", " ");
        htmlStr = htmlStr.replace("&amp;", "&");

        //定义script的正则表达式，去除js可以防止注入
        String scriptRegex = "<script[^>]*?>[\\s\\S]*?<\\/script>";
        //定义style的正则表达式，去除style样式，防止css代码过多时只截取到css样式代码
        String styleRegex = "<style[^>]*?>[\\s\\S]*?<\\/style>";
        //定义HTML标签的正则表达式，去除标签，只提取文字内容
        String htmlRegex = "<[^>]+>";
        // 定义一些特殊字符的正则表达式 如：&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
        String specialRegex1 = "\\&[a-zA-Z]{1,10};";
        // 定义一些特殊字符的正则表达式 如：&#xe625;
        String specialRegex2 = "\\&#[a-zA-Z0-9]{1,10};";
        //定义空格,回车,换行符,制表符
        String spaceRegex = "\\s*|\t|\r|\n";

        // 过滤script标签
        htmlStr = htmlStr.replaceAll(scriptRegex, "");
        // 过滤style标签
        htmlStr = htmlStr.replaceAll(styleRegex, "");
        // 过滤html标签
        htmlStr = htmlStr.replaceAll(htmlRegex, "");
        // 去除特殊字符
        htmlStr = htmlStr.replaceAll(specialRegex1, "");
        htmlStr = htmlStr.replaceAll(specialRegex2, "");
        // 过滤空格等
        htmlStr = htmlStr.replaceAll(spaceRegex, "");

        return htmlStr.trim();
    }

    /**
     * 两个字符串相似度匹配
     *
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
        // 初始化第一列
        for (i = 0; i <= n; i++) {
            d[i][0] = i;
        }

        // 初始化第一行
        for (j = 0; j <= m; j++) {
            d[0][j] = j;
        }

        // 遍历str
        for (i = 1; i <= n; i++) {
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