package io.mixeway.scanmanager.model;

import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Builder
public class AssetToCreate {
	private String hostname;
	private String ip;
	private String routingDomain;

}
