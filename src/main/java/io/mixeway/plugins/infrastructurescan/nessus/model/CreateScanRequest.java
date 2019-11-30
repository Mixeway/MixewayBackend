package io.mixeway.plugins.infrastructurescan.nessus.model;

import java.util.List;

import io.mixeway.db.entity.NessusScan;
import org.apache.tomcat.util.buf.StringUtils;

public class CreateScanRequest {
	private String uuid;
	private Settings settings;
	public String getUuid() {
		return uuid;
	}
	public void setUuid(String uuid) {
		this.uuid = uuid;
	}
	public Settings getSettings() {
		return settings;
	}
	public void setSettings(Settings settings) {
		this.settings = settings;
	}
	
	public CreateScanRequest(NessusScan scanner, String uuid, String name, String description, List<String> targets) {
		Settings s = new Settings();
		s.setName(name);
		s.setDescription(description);
		s.setFolder_id(scanner.getNessus().getFolderId());
		s.setText_targets(StringUtils.join(targets, ','));
		this.setUuid(uuid);
		this.setSettings(s);
	}

}
