/*
 * @created  2020-08-21 : 12:59
 * @project  MixewayScanner
 * @author   siewer
 */
package io.mixeway.rest.profile.model;

public class UserProfile {
    private String username;
    private int projects;
    private int vulns;
    private String password;
    private boolean passwordAuthEnabled;
    private String role;

    public UserProfile(String username, int projects, int vulns, String password, boolean passwordAuthEnabled, String role) {
        this.username = username;
        this.projects = projects;
        this.role = role;
        this.vulns = vulns;
        this.password = password;
        this.passwordAuthEnabled = passwordAuthEnabled;
    }


    public String getRole() {
        return role;
    }

    public void setRole(String role) {
        this.role = role;
    }

    public boolean isPasswordAuthEnabled() {
        return passwordAuthEnabled;
    }

    public void setPasswordAuthEnabled(boolean passwordAuthEnabled) {
        this.passwordAuthEnabled = passwordAuthEnabled;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public int getProjects() {
        return projects;
    }

    public void setProjects(int projects) {
        this.projects = projects;
    }

    public int getVulns() {
        return vulns;
    }

    public void setVulns(int vulns) {
        this.vulns = vulns;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }
}
