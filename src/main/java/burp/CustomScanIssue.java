package burp;

import java.net.URL;

public class CustomScanIssue implements IScanIssue {
    private URL url;
    private String issueName;
    private int issueType;
    private String severity;
    private String confidence;
    private String issueBackground;
    private String remediationBackground;
    private String issueDetail;
    private String remediationDetail;
    private IHttpRequestResponse[] httpMessages;
    private IHttpService httpService;

    public CustomScanIssue(
            URL url,
            String issueName,
            int issueType,
            String severity,
            String confidence,
            String issueBackground,
            String remediationBackground,
            String issueDetail,
            String remediationDetail,
            IHttpRequestResponse[] httpMessages,
            IHttpService httpService) {
        this.url = url;
        this.issueName = issueName;
        this.issueType = issueType;
        this.severity = severity;
        this.confidence = confidence;
        this.issueBackground = issueBackground;
        this.remediationBackground = remediationBackground;
        this.issueDetail = issueDetail;
        this.remediationDetail = remediationDetail;
        this.httpMessages = httpMessages;
        this.httpService = httpService;
    }

    @Override
    public URL getUrl() {
        return this.url;
    }

    @Override
    public String getIssueName() {
        return this.issueName;
    }

    @Override
    public int getIssueType() {
        return this.issueType;
    }

    @Override
    public String getSeverity() {
        return this.severity;
    }

    @Override
    public String getConfidence() {
        return this.confidence;
    }

    @Override
    public String getIssueBackground() {
        return this.issueBackground;
    }

    @Override
    public String getRemediationBackground() {
        return this.remediationBackground;
    }

    @Override
    public String getIssueDetail() {
        return this.issueDetail;
    }

    @Override
    public String getRemediationDetail() {
        return this.remediationDetail;
    }

    @Override
    public IHttpRequestResponse[] getHttpMessages() {
        return this.httpMessages;
    }

    @Override
    public IHttpService getHttpService() {
        return this.httpService;
    }
}