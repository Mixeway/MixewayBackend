package io.mixeway.pojo;

import io.mixeway.db.entity.Asset;

public class AssetListDto {
	Asset asset;
	String description;
	int infraVuln;
	public Asset getAsset() {
		return asset;
	}
	public void setAsset(Asset asset) {
		this.asset = asset;
	}
	public String getDescription() {
		return description;
	}
	public void setDescription(String description) {
		this.description = description;
	}
	public int getInfraVuln() {
		return infraVuln;
	}
	public void setInfraVuln(int infraVuln) {
		this.infraVuln = infraVuln;
	}
	

}
