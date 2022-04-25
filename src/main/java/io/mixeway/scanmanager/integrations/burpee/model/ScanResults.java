package io.mixeway.scanmanager.integrations.burpee.model;

import java.util.List;

public class ScanResults {
    String scan_status;
    List<IssueEvents> issue_events;

    public String getScan_status() {
        return scan_status;
    }

    public void setScan_status(String scan_status) {
        this.scan_status = scan_status;
    }

    public List<IssueEvents> getIssue_events() {
        return issue_events;
    }

    public void setIssue_events(List<IssueEvents> issue_events) {
        this.issue_events = issue_events;
    }
}
