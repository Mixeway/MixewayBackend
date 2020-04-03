package io.mixeway.db.entity;

import javax.persistence.*;

import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.util.Objects;

@Entity
@EntityScan
@Table(name = "scannertype")
@EntityListeners(AuditingEntityListener.class)
public class ScannerType {
	private Long id;
	private String name;
	private boolean authsecrettoken;
	private boolean authaccesstoken;
	private boolean authusername;
	private boolean authpassword;
	private boolean authcloudctrltoken;
	private boolean authapikey;
	private String category;
	private int scanLimit;

	@Column(name="scanlimit")
	public int getScanLimit() {
		return scanLimit;
	}

	public void setScanLimit(int scanLimit) {
		this.scanLimit = scanLimit;
	}

	public String getCategory() {
		return category;
	}

	public void setCategory(String category) {
		this.category = category;
	}

	@Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
	public Long getId() {
		return id;
	}
	public void setId(Long id) {
		this.id = id;
	}
	public String getName() {
		return name;
	}
	public void setName(String name) {
		this.name = name;
	}

	public boolean isAuthsecrettoken() {
		return authsecrettoken;
	}

	public void setAuthsecrettoken(boolean authsecrettoken) {
		this.authsecrettoken = authsecrettoken;
	}

	public boolean isAuthaccesstoken() {
		return authaccesstoken;
	}

	public void setAuthaccesstoken(boolean authaccesstoken) {
		this.authaccesstoken = authaccesstoken;
	}

	public boolean isAuthusername() {
		return authusername;
	}

	public void setAuthusername(boolean authusername) {
		this.authusername = authusername;
	}

	public boolean isAuthpassword() {
		return authpassword;
	}

	public void setAuthpassword(boolean authpassword) {
		this.authpassword = authpassword;
	}

	public boolean isAuthcloudctrltoken() {
		return authcloudctrltoken;
	}

	public void setAuthcloudctrltoken(boolean authcloudctrltoken) {
		this.authcloudctrltoken = authcloudctrltoken;
	}

	public boolean isAuthapikey() {
		return authapikey;
	}

	public void setAuthapikey(boolean authapikey) {
		this.authapikey = authapikey;
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) return true;
		if (!(o instanceof ScannerType)) return false;
		ScannerType scannerType = (ScannerType) o;
		return Objects.equals(getId(), scannerType.getId());
	}

	@Override
	public int hashCode() {
		return Objects.hash(getId());
	}
}
