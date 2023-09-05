package io.mixeway.utils;

import io.mixeway.db.entity.ProjectVulnerabilityAudit;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class VulnerabiltyAudit {

    private String inserted;
    private String start;
    private String end;
    private int occurances;
    private EventType eventType;
    private String ticketid;
    //private String severity;
    //private String source;
    private Long id;
    private int revType;

    public VulnerabiltyAudit(ProjectVulnerabilityAudit pva, String start, String end, int occurances){
        this.revType = pva.getRevtype();
        this.inserted = pva.getInserted();
        if (pva.getRevtype() == 0){
            this.eventType = EventType.CREATED;
        } else if (pva.getRevtype() == 1){
            this.eventType = EventType.UPDATED;
        } else if (pva.getRevtype() == 2){
            this.eventType = EventType.RESOLVED;
        }
        this.ticketid = pva.getTicketid();
        this.id = pva.getId().getId();
        //this.severity = pva.getSeverity();
       // this.source = pva.getVulnerabilitySource().getName();
        this.start = start;
        this.end = end;
        this.occurances = occurances;
    }

    public void increaseOccurancies() {
        this.occurances++;
    }
}
