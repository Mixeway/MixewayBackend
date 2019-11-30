package io.mixeway.plugins.webappscan.model;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

public class WebAppScanModel {

	private String url;
	private Boolean isPublic;
	List<RequestHeaders> headers;
	List<CustomCookie> cookies;
	@JsonProperty("codeGroup")
	private String codeGroup;
	@JsonProperty("codeProject")
	private String codeProject;

	public WebAppScanModel(){}

	public List<CustomCookie> getCookies() {
		return cookies;
	}

	public void setCookies(List<CustomCookie> cookies) {
		this.cookies = cookies;
	}

	public Boolean getPublic() {
		return isPublic;
	}

	public void setPublic(Boolean aPublic) {
		isPublic = aPublic;
	}

	public String getCodeGroup() {
		return codeGroup;
	}
	public void setCodeGroup(String codeGroup) {
		this.codeGroup = codeGroup;
	}
	public String getCodeProject() {
		return codeProject;
	}
	public void setCodeProject(String codeProject) {
		this.codeProject = codeProject;
	}
	public String getUrl() {
		return url;
	}
	public void setUrl(String url) {
		this.url = url;
	}
	public Boolean getIsPublic() {
		return isPublic;
	}
	public void setIsPublic(Boolean isPublic) {
		this.isPublic = isPublic;
	}
	public List<RequestHeaders> getHeaders() {
		return headers;
	}
	public void setHeaders(List<RequestHeaders> headers) {
		this.headers = headers;
	}


}
