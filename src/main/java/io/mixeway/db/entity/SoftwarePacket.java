package io.mixeway.db.entity;

import java.util.Objects;
import java.util.Set;

import javax.persistence.CascadeType;
import javax.persistence.Entity;
import javax.persistence.EntityListeners;
import javax.persistence.FetchType;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.ManyToMany;
import javax.persistence.Table;

import com.fasterxml.jackson.annotation.JsonIgnore;
import io.mixeway.utils.VulnSource;
import org.codehaus.jackson.annotate.JsonIgnoreProperties;
import org.hibernate.annotations.OnDelete;
import org.hibernate.annotations.OnDeleteAction;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

@Entity
@EntityScan
@Table(name = "softwarepacket")
@EntityListeners(AuditingEntityListener.class)
@JsonIgnoreProperties({"hibernateLazyInitializer", "handler"})
public class SoftwarePacket implements VulnSource {
	
	@JsonIgnore private Long id;
	private String name;
	@JsonIgnore private Set<Asset> assets;
	@JsonIgnore private Set<CodeProject> codeProjects;
	@JsonIgnore private Boolean uptated;
	@ManyToMany(fetch = FetchType.LAZY,
			mappedBy = "softwarePackets")
	@OnDelete(action = OnDeleteAction.CASCADE)
	public Set<CodeProject> getCodeProjects() {
		return codeProjects;
	}

	public void setCodeProjects(Set<CodeProject> codeProjects) {
		this.codeProjects = codeProjects;
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
	@ManyToMany(fetch = FetchType.LAZY,
            cascade = {
                CascadeType.PERSIST,
                CascadeType.MERGE
            },
            mappedBy = "softwarePackets")
	@OnDelete(action = OnDeleteAction.CASCADE)
	public Set<Asset> getAssets() {
		return assets;
	}
	public void setAssets(Set<Asset> assets) {
		this.assets = assets;
	}
	public Boolean getUptated() {
		return uptated;
	}
	public void setUptated(Boolean uptated) {
		this.uptated = uptated;
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) return true;
		if (!(o instanceof SoftwarePacket)) return false;
		SoftwarePacket packet = (SoftwarePacket) o;
		return Objects.equals(getId(), packet.getId());
	}

	@Override
	public int hashCode() {
		return getClass().hashCode();
	}
}
