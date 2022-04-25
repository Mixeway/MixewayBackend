package io.mixeway.scanmanager.integrations.nessus.model;

import io.mixeway.db.entity.InfraScan;
import org.apache.tomcat.util.buf.StringUtils;

import java.util.List;

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
	
	public CreateScanRequest(InfraScan scanner, String uuid, String name, String description, List<String> targets) {
		Settings s = new Settings();
		s.setName(name);
		s.setDescription(description);
		s.setFolder_id(scanner.getNessus().getFolderId());
		s.setText_targets(StringUtils.join(targets, ','));
		this.setUuid(uuid);
		this.setSettings(s);
	}

}
