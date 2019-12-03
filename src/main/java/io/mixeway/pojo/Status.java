package io.mixeway.pojo;

import org.codehaus.jettison.json.JSONException;
import org.codehaus.jettison.json.JSONObject;

public class Status {
	
	private String status;
	private String requestId;

	public String getRequestId() {
		return requestId;
	}

	public void setRequestId(String requestId) {
		this.requestId = requestId;
	}

	public String getStatus() {
		return status;
	}

	public void setStatus(String status) {
		this.status = status;
	}
	
	public Status(String status) {
		this.status = status;
	}
	public Status(String status,String requestId) {
		this.status = status;
		this.requestId = requestId;
	}
	public String toString() { 
		JSONObject o = new JSONObject();
		try {
			o.append("status", this.getStatus());
			if (this.getRequestId()!=null && !this.getRequestId().equals(""))
				o.append("requestId", this.getRequestId());
		} catch (JSONException e) {
			e.printStackTrace();
		}
	    return o.toString();
	} 
}
