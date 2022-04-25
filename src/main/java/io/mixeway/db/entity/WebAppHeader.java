package io.mixeway.db.entity;

import javax.persistence.*;

import org.hibernate.annotations.OnDelete;
import org.hibernate.annotations.OnDeleteAction;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import com.fasterxml.jackson.annotation.JsonIgnore;

@Entity
@EntityScan
@Table(name = "webappheader")
@EntityListeners(AuditingEntityListener.class)
public class WebAppHeader {
	
	private Long id;
	private String headerName;
	private String headerValue;
	private WebApp webApp;
	@Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
	public Long getId() {
		return id;
	}
	public void setId(Long id) {
		this.id = id;
	}
	@Column(name="headername")
	public String getHeaderName() {
		return headerName;
	}
	public void setHeaderName(String headerName) {
		this.headerName = headerName;
	}
	@Column(name="headervalue")
	public String getHeaderValue() {
		return headerValue;
	}
	public void setHeaderValue(String headerValue) {
		this.headerValue = headerValue;
	}
	@ManyToOne(fetch = FetchType.LAZY, optional = true )
    @JoinColumn(name = "webapp_id", nullable = true)
    @OnDelete(action = OnDeleteAction.CASCADE)
    @JsonIgnore
	public WebApp getWebApp() {
		return webApp;
	}
	public void setWebApp(WebApp webApp) {
		this.webApp = webApp;
	}

}
