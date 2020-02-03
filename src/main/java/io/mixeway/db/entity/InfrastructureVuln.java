package io.mixeway.db.entity;

import javax.persistence.*;

import io.mixeway.pojo.Vulnerability;
import org.hibernate.annotations.CacheConcurrencyStrategy;
import org.hibernate.annotations.OnDelete;
import org.hibernate.annotations.OnDeleteAction;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

@Entity
@EntityScan
@Table(name = "infrastructurevuln")
@EntityListeners(AuditingEntityListener.class)
@Cacheable
@org.hibernate.annotations.Cache(usage = CacheConcurrencyStrategy.READ_WRITE)
public class InfrastructureVuln implements Vulnerability {
	private Long id;
	private Interface intf;
	private String name;
	private String severity;
	private String port;
	private String description;
	private String inserted;
	private Status status;
	private String ticketId;

	@Column(name="ticketid")
	@Override
	public String getTicketId() {
		return ticketId;
	}

	@Override
	public void setTicketId(String ticketId) {
		this.ticketId = ticketId;
	}

	@ManyToOne(fetch = FetchType.EAGER, optional = true)
	@JoinColumn(name = "status_id", nullable = true)
	@OnDelete(action = OnDeleteAction.CASCADE)
	public Status getStatus() {
		return status;
	}

	public void setStatus(Status status) {
		this.status = status;
	}

	public String getInserted() {
		return inserted;
	}
	public void setInserted(String inserted) {
		this.inserted = inserted;
	}
	@Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
	public Long getId() {
		return id;
	}
	public void setId(Long id) {
		this.id = id;
	}
	@ManyToOne(fetch = FetchType.EAGER, optional = false)
    @JoinColumn(name = "interface_id", nullable = false)
    @OnDelete(action = OnDeleteAction.CASCADE)
	public Interface getIntf() {
		return intf;
	}
	public void setIntf(Interface intf) {
		this.intf = intf;
	}
	public String getName() {
		return name;
	}
	public void setName(String name) {
		this.name = name;
	}
	@Column(name="threat")
	public String getSeverity() {
		return severity;
	}
	public void setSeverity(String threat) {
		this.severity = threat;
	}
	public String getPort() {
		return port;
	}
	public void setPort(String port) {
		this.port = port;
	}
	@Override
	public String getDescription() {
		return description;
	}
	@Override
	public void setDescription(String description) {
		this.description = description;
	}



}
