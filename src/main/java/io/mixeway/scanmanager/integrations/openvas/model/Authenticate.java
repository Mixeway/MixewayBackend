package io.mixeway.scanmanager.integrations.openvas.model;


public class Authenticate {
	private Credentials credentials;
	
	
	public Credentials getCredentials() {
		return credentials;
	}


	public void setCredentials(Credentials credentials) {
		this.credentials = credentials;
	}


	public Authenticate(User user) {
		this.setCredentials(new Credentials(user));
	}
	public Authenticate(){}
	

}
