package burp.Application.ShiroCipherKeyDetection;

import burp.Application.ShiroFingerprintDetection.ShiroFingerprint;
import burp.Application.ShiroCipherKeyDetection.ExtensionMethod.*;

import burp.IBurpExtenderCallbacks;
import burp.IHttpRequestResponse;

public class ShiroCipherKey {

    private ShiroCipherKeyMethodInterface shiroCipherKeyMethod;

    public ShiroCipherKey(IBurpExtenderCallbacks callbacks,
                          IHttpRequestResponse baseRequestResponse,
                          ShiroFingerprint shiroFingerprint) {

        this.init(callbacks, baseRequestResponse, shiroFingerprint);

    }

    private void init(IBurpExtenderCallbacks callbacks,
                      IHttpRequestResponse baseRequestResponse,
                      ShiroFingerprint shiroFingerprint) {

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
                "tiVV6g3uZBGfgshesAQbjA==", "ZAvph3dsQs0FSL3SDFAdag==" };

        ShiroCipherKeyMethod1 shiroCipherKey = new ShiroCipherKeyMethod1(
                                        callbacks,
                                        baseRequestResponse,
                                        keys,
                                        shiroFingerprint.run().getRequestDefaultRememberMeCookieName());

        this.shiroCipherKeyMethod = shiroCipherKey;
    }

    public ShiroCipherKeyMethodInterface run() {
        return this.shiroCipherKeyMethod;
    }
}
