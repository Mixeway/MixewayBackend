package io.mixeway.plugins.webappscan.model;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import io.mixeway.db.entity.WebApp;
import io.mixeway.db.entity.WebAppHeader;

import java.util.ArrayList;
import java.util.List;

public class Headers {
	final static Logger log = LoggerFactory.getLogger(Headers.class);
	
	private String[] custom_headers;

	public static Logger getLog() {
		return log;
	}



	public String[] getCustom_headers() {
		return custom_headers;
	}

	public void setCustom_headers(String[] custom_headers) {
		this.custom_headers = custom_headers;
	}
	
	public Headers(WebApp wa) {
		String[] h = new String[wa.getHeaders().size()];
		List<CustomCookie> customCookies = new ArrayList<>();
		int i = 0;
		for (WebAppHeader header : wa.getHeaders()) {
			h[i] = header.getHeaderName()+":"+header.getHeaderValue();
			i++;
		}

		this.setCustom_headers(h);
	}

}
