package io.mixeway.integrations.codescan.plugin.fortify.model;

public class FortifyVuln {
    String issueName;
    String friority;
    Long id;
    String primaryTag;
    String fullFileName;
    int lineNumber;
    String issueInstanceId;

    public String getIssueName() {
        return issueName;
    }

    public void setIssueName(String issueName) {
        this.issueName = issueName;
    }

    public String getFriority() {
        return friority;
    }

    public void setFriority(String friority) {
        this.friority = friority;
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getPrimaryTag() {
        return primaryTag;
    }

    public void setPrimaryTag(String primaryTag) {
        this.primaryTag = primaryTag;
    }

    public String getFullFileName() {
        return fullFileName;
    }

    public void setFullFileName(String fullFileName) {
        this.fullFileName = fullFileName;
    }

    public int getLineNumber() {
        return lineNumber;
    }

    public void setLineNumber(int lineNumber) {
        this.lineNumber = lineNumber;
    }

    public String getIssueInstanceId() {
        return issueInstanceId;
    }

    public void setIssueInstanceId(String issueInstanceId) {
        this.issueInstanceId = issueInstanceId;
    }
}
