/*
 * @created  2020-08-21 : 12:59
 * @project  MixewayScanner
 * @author   siewer
 */
package io.mixeway.api.profile.model;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
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
}
