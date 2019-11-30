package io.mixeway.db.entity;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.EntityListeners;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.Table;

import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

@Entity
@EntityScan
@Table(name = "loginsequence")
@EntityListeners(AuditingEntityListener.class)
public class LoginSequence {
	
	private Long id;
	private String name;
	private String loginSequenceText;
	@Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
	public Long getId() {
		return id;
	}
	public void setId(Long id) {
		this.id = id;
	}
	@Column(name="loginsequencetext")
	public String getLoginSequenceText() {
		return loginSequenceText;
	}
	public void setLoginSequenceText(String loginSequenceText) {
		this.loginSequenceText = loginSequenceText;
	}
	public String getName() {
		return name;
	}
	public void setName(String name) {
		this.name = name;
	}
	
	

}
