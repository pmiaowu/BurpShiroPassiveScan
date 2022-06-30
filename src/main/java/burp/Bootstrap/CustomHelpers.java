package burp.Bootstrap;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

public class CustomHelpers {
    /**
     * 获取精确到秒的时间戳
     *
     * @param date
     * @return Integer
     */
    public static Integer getSecondTimestamp(Date date) {
        if (null == date) {
            return 0;
        }
        String timestamp = String.valueOf(date.getTime() / 1000);
        return Integer.valueOf(timestamp);
    }

    /**
     * 列表块分割函数
     * 功能: 把列表按照size分割成指定的list快返回
     * 例子1:
     * a = [1, 2, 3, 4, 5, 6, 7, 8, 9]
     * listChunkSplit(a, 2)
     * 返回: [[1, 2, 3, 4, 5], [6, 7, 8, 9]]
     * 例子2:
     * a = [1, 2, 3, 4, 5, 6, 7, 8, 9]
     * listChunkSplit(a, 10)
     * 返回: [[1], [2], [3], [4], [5], [6], [7], [8], [9]]
     *
     * @param dataSource 数据源
     * @param groupSize  一个整数, 规定最多分成几个list
     * @return List<List < String>>
     */
    public static List<List<String>> listChunkSplit(List<String> dataSource, Integer groupSize) {
        List<List<String>> result = new ArrayList<>();

        if (dataSource.size() == 0 || groupSize == 0) {
            return result;
        }

        // 偏移量
        int offset = 0;

        // 计算 商
        int number = dataSource.size() / groupSize;

        // 计算 余数
        int remainder = dataSource.size() % groupSize;

        for (int i = 0; i < groupSize; i++) {
            List<String> value = null;
            if (remainder > 0) {
                value = dataSource.subList(i * number + offset, (i + 1) * number + offset + 1);
                remainder--;
                offset++;
            } else {
                value = dataSource.subList(i * number + offset, (i + 1) * number + offset);
            }

            if (value.size() == 0) {
                break;
            }

            result.add(value);
        }

        return result;
    }
}