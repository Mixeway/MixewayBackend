package io.mixeway.scanmanager.model;

import io.mixeway.db.entity.WebApp;
import io.mixeway.db.entity.WebAppHeader;
import lombok.Getter;
import lombok.Setter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Getter
@Setter
public class Headers {

	private String[] custom_headers;

	public Headers(WebApp wa) {
		String[] h = new String[wa.getHeaders().size()];
		int i = 0;
		for (WebAppHeader header : wa.getHeaders()) {
			h[i] = header.getHeaderName()+":"+header.getHeaderValue();
			i++;
		}

		this.setCustom_headers(h);
	}

}
