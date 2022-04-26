package io.mixeway.scanmanager.model;

import lombok.*;

@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AssetToCreate {
	private String hostname;
	private String ip;
	private String routingDomain;

}
