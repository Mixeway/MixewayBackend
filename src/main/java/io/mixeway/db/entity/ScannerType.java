package io.mixeway.db.entity;

import javax.persistence.*;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.util.Objects;

@Entity
@EntityScan
@Table(name = "scannertype")
@EntityListeners(AuditingEntityListener.class)
@Getter
@Setter
public class ScannerType {
	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Long id;
	private String name;
	private boolean authsecrettoken;
	private boolean authaccesstoken;
	private boolean authusername;
	private boolean authpassword;
	private boolean authcloudctrltoken;
	private boolean authapikey;
	private String category;
	@Column(name="scanlimit")
	private int scanLimit;

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
