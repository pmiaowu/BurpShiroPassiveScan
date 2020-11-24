package burp.Application.ShiroCipherKeyDetection;

import burp.Application.ShiroFingerprintDetection.ShiroFingerprint;
import burp.Application.ShiroCipherKeyDetection.ExtensionMethod.*;

import burp.IBurpExtenderCallbacks;
import burp.IHttpRequestResponse;

import burp.Bootstrap.Encrypt.*;

import java.util.Date;

public class ShiroCipherKey {

    private ShiroCipherKeyMethodInterface shiroCipherKeyMethod;

    // 该模块启动日期
    private Date startDate = new Date();

    // 程序最大执行时间,单位为秒
    // 会根据payload的添加而添加
    private int maxExecutionTime = 120;

    public ShiroCipherKey(IBurpExtenderCallbacks callbacks,
                          IHttpRequestResponse baseRequestResponse,
                          ShiroFingerprint shiroFingerprint,
                          String callClassName) {
        this.init(callbacks, baseRequestResponse, shiroFingerprint, callClassName);
    }

    private ShiroCipherKeyMethodInterface init(IBurpExtenderCallbacks callbacks,
                                               IHttpRequestResponse baseRequestResponse,
                                               ShiroFingerprint shiroFingerprint,
                                               String callClassName) {

        String[] keys = {
                "kPH+bIxk5D2deZiIxcaaaA==", "Z3VucwAAAAAAAAAAAAAAAA==", "wGiHplamyXlVB11UXWol8g==",
                "2AvVhdsgUs0FSA3SDFAdag==", "3AvVhmFLUs0KTA3Kprsdag==", "4AvVhmFLUs0KTA3Kprsdag==",
                "bWljcm9zAAAAAAAAAAAAAA==", "WcfHGU25gNnTxTlmJMeSpw==", "fCq+/xW488hMTCD+cmJ3aQ==",
                "kPv59vyqzj00x11LXJZTjJ2UHW48jzHN", "6ZmI6I2j5Y+R5aSn5ZOlAA==", "1QWLxg+NYmxraMoxAXu/Iw==",
                "a2VlcE9uR29pbmdBbmRGaQ==", "5aaC5qKm5oqA5pyvAAAAAA==", "1AvVhdsgUs0FSA3SDFAdag==",
                "5RC7uBZLkByfFfJm22q/Zw==", "3AvVhdAgUs0FSA4SDFAdBg==", "a3dvbmcAAAAAAAAAAAAAAA==",
                "eXNmAAAAAAAAAAAAAAAAAA==", "U0hGX2d1bnMAAAAAAAAAAA==", "Ymx1ZXdoYWxlAAAAAAAAAA==",
                "L7RioUULEFhRyxM7a2R/Yg==", "UGlzMjAxNiVLeUVlXiEjLw==", "bWluZS1hc3NldC1rZXk6QQ==",
                "ZUdsaGJuSmxibVI2ZHc9PQ==", "7AvVhmFLUs0KTA3Kprsdag==", "MTIzNDU2Nzg5MGFiY2RlZg==",
                "OY//C4rhfwNxCQAQCrQQ1Q==", "bTBANVpaOUw0ampRWG43TVJFcF5iXjdJ", "FP7qKJzdJOGkzoQzo2wTmA==",
                "nhNhwZ6X7xzgXnnZBxWFQLwCGQtJojL3", "LEGEND-CAMPUS-CIPHERKEY==", "r0e3c16IdVkouZgk1TKVMg==",
                "ZWvohmPdUsAWT3=KpPqda", "k3+XHEg6D8tb2mGm7VJ3nQ==", "U3ByaW5nQmxhZGUAAAAAAA==",
                "tiVV6g3uZBGfgshesAQbjA==", "ZAvph3dsQs0FSL3SDFAdag==", "0AvVhmFLUs0KTA3Kprsdag==",
                "25BsmdYwjnfcWmnhAciDDg==", "3JvYhmBLUs0ETA5Kprsdag==", "5AvVhmFLUs0KTA3Kprsdag==",
                "6AvVhmFLUs0KTA3Kprsdag==", "6NfXkC7YVCV5DASIrEm1Rg==", "cmVtZW1iZXJNZQAAAAAAAA==",
                "8AvVhmFLUs0KTA3Kprsdag==", "8BvVhmFLUs0KTA3Kprsdag==", "9AvVhmFLUs0KTA3Kprsdag==",
                "OUHYQzxQ/W9e/UjiAGu6rg==", "aU1pcmFjbGVpTWlyYWNsZQ==", "bXRvbnMAAAAAAAAAAAAAAA==",
                "5J7bIJIV0LQSN3c9LPitBQ==", "bya2HkYo57u6fWh5theAWw==", "f/SY5TIve5WWzT4aQlABJA==",
                "WuB+y2gcHRnY2Lg9+Aqmqg==", "3qDVdLawoIr1xFd6ietnwg==", "YI1+nBV//m7ELrIyDHm6DQ==",
                "6Zm+6I2j5Y+R5aS+5ZOlAA==", "2A2V+RFLUs+eTA3Kpr+dag==", "6ZmI6I2j3Y+R1aSn5BOlAA==",
                "SkZpbmFsQmxhZGUAAAAAAA==", "2cVtiE83c4lIrELJwKGJUw==", "fsHspZw/92PrS3XrPW+vxw==",
                "XTx6CKLo/SdSgub+OPHSrw==", "sHdIjUN6tzhl8xZMG3ULCQ==", "O4pdf+7e+mZe8NyxMTPJmQ==",
                "HWrBltGvEZc14h9VpMvZWw==", "rPNqM6uKFCyaL10AK51UkQ==", "Y1JxNSPXVwMkyvES/kJGeQ==",
                "lT2UvDUmQwewm6mMoiw4Ig==", "MPdCMZ9urzEA50JDlDYYDg==", "xVmmoltfpb8tTceuT5R7Bw==",
                "c+3hFGPjbgzGdrC+MHgoRQ==", "ClLk69oNcA3m+s0jIMIkpg==", "Bf7MfkNR0axGGptozrebag==",
                "1tC/xrDYs8ey+sa3emtiYw==", "ZmFsYWRvLnh5ei5zaGlybw==", "cGhyYWNrY3RmREUhfiMkZA==",
                "IduElDUpDDXE677ZkhhKnQ==", "yeAAo1E8BOeAYfBlm4NG9Q==", "cGljYXMAAAAAAAAAAAAAAA==",
                "2itfW92XazYRi5ltW0M2yA==", "XgGkgqGqYrix9lI6vxcrRw==", "ertVhmFLUs0KTA3Kprsdag==",
                "5AvVhmFLUS0ATA4Kprsdag==", "s0KTA3mFLUprK4AvVhsdag==", "hBlzKg78ajaZuTE0VLzDDg==",
                "9FvVhtFLUs0KnA3Kprsdyg==", "d2ViUmVtZW1iZXJNZUtleQ==", "yNeUgSzL/CfiWw1GALg6Ag==",
                "NGk/3cQ6F5/UNPRh8LpMIg==", "4BvVhmFLUs0KTA3Kprsdag==", "MzVeSkYyWTI2OFVLZjRzZg==",
                "CrownKey==a12d/dakdad", "empodDEyMwAAAAAAAAAAAA==", "A7UzJgh1+EWj5oBFi+mSgw==",
                "c2hpcm9fYmF0aXMzMgAAAA==", "i45FVt72K2kLgvFrJtoZRw==", "66v1O8keKNV3TTcGPK1wzg==",
                "U3BAbW5nQmxhZGUAAAAAAA==", "ZnJlc2h6Y24xMjM0NTY3OA==", "Jt3C93kMR9D5e8QzwfsiMw==",
                "MTIzNDU2NzgxMjM0NTY3OA==", "vXP33AonIp9bFwGl7aT7rA==", "V2hhdCBUaGUgSGVsbAAAAA==",
                "Q01TX0JGTFlLRVlfMjAxOQ==", "Is9zJ3pzNh2cgTHB4ua3+Q==", "SDKOLKn2J1j/2BHjeZwAoQ==",
                "NsZXjXVklWPZwOfkvk6kUA==", "GAevYnznvgNCURavBhCr1w==", "zSyK5Kp6PZAAjlT+eeNMlg==",
                "bXdrXl9eNjY2KjA3Z2otPQ==", "RVZBTk5JR0hUTFlfV0FPVQ==", "WkhBTkdYSUFPSEVJX0NBVA==",
                "GsHaWo4m1eNbE0kNSMULhg==", "l8cc6d2xpkT1yFtLIcLHCg==", "KU471rVNQ6k7PQL4SqxgJg==",
                "kPH+bIxk5D2deZiIxcabaA==", "kPH+bIxk5D2deZiIxcacaA==", "4AvVhdsgUs0F563SDFAdag==",
                "FL9HL9Yu5bVUJ0PDU1ySvg==", "fdCEiK9YvLC668sS43CJ6A==", "FJoQCiz0z5XWz2N2LyxNww==",
                "HeUZ/LvgkO7nsa18ZyVxWQ==", "HoTP07fJPKIRLOWoVXmv+Q==", "iycgIIyCatQofd0XXxbzEg==",
                "m0/5ZZ9L4jjQXn7MREr/bw==", "NoIw91X9GSiCrLCF03ZGZw==", "oPH+bIxk5E2enZiIxcqaaA==",
                "QAk0rp8sG0uJC4Ke2baYNA==", "Rb5RN+LofDWJlzWAwsXzxg==", "s2SE9y32PvLeYo+VGFpcKA==",
                "SrpFBcVD89eTQ2icOD0TMg==", "Us0KvVhTeasAm43KFLAeng==", "YWJjZGRjYmFhYmNkZGNiYQ==",
                "zIiHplamyXlVB11UXWol8g==", "ZjQyMTJiNTJhZGZmYjFjMQ=="
        };

        // 获得最终的程序最大执行时间
        int keyLength = keys.length;
        if (keyLength > 20) {
            this.maxExecutionTime += (keyLength - 20) * 2;
        }

        if (callClassName.equals("ShiroCipherKeyMethod2")) {
            ShiroCipherKeyMethod2 shiroCipherKey = new ShiroCipherKeyMethod2(
                    callbacks,
                    baseRequestResponse,
                    keys,
                    shiroFingerprint,
                    this.startDate,
                    this.maxExecutionTime,
                    new CbcEncrypt());

            if (shiroCipherKey.isShiroCipherKeyExists()) {
                this.shiroCipherKeyMethod = shiroCipherKey;
            } else {
                ShiroCipherKeyMethod2 shiroCipherKey2 = new ShiroCipherKeyMethod2(
                        callbacks,
                        baseRequestResponse,
                        keys,
                        shiroFingerprint,
                        this.startDate,
                        this.maxExecutionTime,
                        new GcmEncrypt());
                this.shiroCipherKeyMethod = shiroCipherKey2;
            }

            return this.shiroCipherKeyMethod;
        }

        throw new IllegalArgumentException(
                String.format("ShiroCipherKey模块-对不起您输入的 %s 扩展找不到", callClassName));
    }

    public ShiroCipherKeyMethodInterface run() {
        return this.shiroCipherKeyMethod;
    }
}
