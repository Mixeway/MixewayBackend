package io.mixeway.plugins.audit.vulners.model;

import java.util.List;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.google.gson.annotations.SerializedName;

public class VulnersRequest {
	String os;
	Double version;
	@SerializedName("package")
	List<String> packet;
	public String getOs() {
		return os;
	}
	public void setOs(String os) {
		this.os = os;
	}
	public Double getVersion() {
		return version;
	}
	public void setVersion(Double version) {
		this.version = version;
	}
	@JsonProperty("package")
	@SerializedName("package")
	public List<String> getPacket() {
		return packet;
	}
	public void setPacket(List<String> packet) {
		this.packet = packet;
	}
	
	
}
