package io.mixeway.db.entity;

import org.hibernate.annotations.OnDelete;
import org.hibernate.annotations.OnDeleteAction;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import javax.persistence.*;

@Entity
@EntityScan
@Table(name = "webappscanstrategy")
@EntityListeners(AuditingEntityListener.class)
public class WebAppScanStrategy {
    Long id;
    ScannerType apiStrategy;
    ScannerType scheduledStrategy;
    ScannerType guiStrategy;

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }
    @ManyToOne(fetch = FetchType.EAGER)
    @JoinColumn(name = "apiscans_id")
    public ScannerType getApiStrategy() {
        return apiStrategy;
    }

    public void setApiStrategy(ScannerType apiStrategy) {
        this.apiStrategy = apiStrategy;
    }

    @ManyToOne(fetch = FetchType.EAGER)
    @JoinColumn(name = "scheduledscans_id")
    public ScannerType getScheduledStrategy() {
        return scheduledStrategy;
    }

    public void setScheduledStrategy(ScannerType scheduledStrategy) {
        this.scheduledStrategy = scheduledStrategy;
    }

    @ManyToOne(fetch = FetchType.EAGER)
    @JoinColumn(name = "guiscans_id")
    public ScannerType getGuiStrategy() {
        return guiStrategy;
    }

    public void setGuiStrategy(ScannerType guiStrategy) {
        this.guiStrategy = guiStrategy;
    }
}
