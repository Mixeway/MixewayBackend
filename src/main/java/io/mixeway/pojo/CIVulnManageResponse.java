package io.mixeway.pojo;

import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.List;

@Builder
@Getter
@Setter
@NoArgsConstructor
public class CIVulnManageResponse {
    String result;
    String commitId;
    Boolean running;
    Boolean inQueue;
    List<VulnManageResponse> vulnManageResponseList;

    public Boolean getRunning() {
        return running;
    }

    public void setRunning(Boolean running) {
        this.running = running;
    }

    public Boolean getInQueue() {
        return inQueue;
    }

    public void setInQueue(Boolean inQueue) {
        this.inQueue = inQueue;
    }

    public String getCommitId() {
        return commitId;
    }

    public void setCommitId(String commitId) {
        this.commitId = commitId;
    }

    public String getResult() {
        return result;
    }

    public void setResult(String result) {
        this.result = result;
    }

    public List<VulnManageResponse> getVulnManageResponseList() {
        return vulnManageResponseList;
    }

    public void setVulnManageResponseList(List<VulnManageResponse> vulnManageResponseList) {
        this.vulnManageResponseList = vulnManageResponseList;
    }
}
