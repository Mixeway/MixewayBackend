package io.mixeway.scanmanager.integrations.vulnauditor.model;

/**
 * @author gsiewruk
 */
public class VulnAuditorResponse {
    Long id;
    int audit;

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public int getAudit() {
        return audit;
    }

    public void setAudit(int audit) {
        this.audit = audit;
    }
}
