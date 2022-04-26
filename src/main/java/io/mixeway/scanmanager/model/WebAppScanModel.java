package io.mixeway.scanmanager.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.List;

@Getter
@Setter
@NoArgsConstructor
public class WebAppScanModel {

	private String url;
	private Boolean isPublic;
	List<RequestHeaders> headers;
	List<CustomCookie> cookies;
	@JsonProperty("codeGroup")
	private String codeGroup;
	@JsonProperty("codeProject")
	private String codeProject;
	private String routingDomain;
	private String username;
	private String password;

}
