package io.mixeway.scanmanager.integrations.burpee.model;

/**
 * @author gsiewruk
 */
public class Scan {
    String ref;
    String status;
    String start_time;

    public String getStart_time() {
        return start_time;
    }

    public void setStart_time(String start_time) {
        this.start_time = start_time;
    }

    public String getRef() {
        return ref;
    }

    public void setRef(String ref) {
        this.ref = ref;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

}
