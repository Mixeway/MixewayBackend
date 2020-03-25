package io.mixeway.integrations.audit.plugins.vulners.model;

import java.util.List;

public class Packets {
	String hostname;
	List<String> ips;
	List<String> packets;
	String os;
	String version;
	
	public String getOs() {
		return os;
	}
	public void setOs(String os) {
		this.os = os;
	}
	public String getVersion() {
		return version;
	}
	public void setVersion(String version) {
		this.version = version;
	}
	public String getHostname() {
		return hostname;
	}
	public void setHostname(String hostname) {
		this.hostname = hostname;
	}
	public List<String> getIps() {
		return ips;
	}
	public void setIps(List<String> ips) {
		this.ips = ips;
	}
	public List<String> getPackets() {
		return packets;
	}
	public void setPackets(List<String> packets) {
		this.packets = packets;
	}
	
	

}
