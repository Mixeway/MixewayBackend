package io.mixeway.scanmanager.integrations.burpee.model;

/**
 * @author gsiewruk
 */
public class AuthLogins {
    String password;
    String username;

    public AuthLogins() {}
    public AuthLogins(String password, String username){
        this.password = password;
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }
}
