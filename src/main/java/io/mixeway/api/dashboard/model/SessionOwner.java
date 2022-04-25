package io.mixeway.api.dashboard.model;

public class SessionOwner {
    String name;
    int logins;

    public int getLogins() {
        return logins;
    }

    public void setLogins(int logins) {
        this.logins = logins;
    }

    public SessionOwner(String name, int logins){
        this.name=name;
        this.logins = logins;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }
}
