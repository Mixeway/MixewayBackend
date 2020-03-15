package io.mixeway.rest.model;

import io.mixeway.db.entity.Project;

import java.util.List;

public class UserModel {
    String userRole;
    String userCN;
    Boolean passwordAuth;
    String userPassword;
    String userUsername;
    List<Project> projects;

    public List<Project> getProjects() {
        return projects;
    }

    public void setProjects(List<Project> projects) {
        this.projects = projects;
    }

    public Boolean getPasswordAuth() {
        return passwordAuth;
    }

    public void setPasswordAuth(Boolean passwordAuth) {
        this.passwordAuth = passwordAuth;
    }

    public String getUserPassword() {
        return userPassword;
    }

    public void setUserPassword(String userPassword) {
        this.userPassword = userPassword;
    }

    public String getUserUsername() {
        return userUsername;
    }

    public void setUserUsername(String userUsername) {
        this.userUsername = userUsername;
    }

    public String getUserRole() {
        return userRole;
    }

    public void setUserRole(String userRole) {
        this.userRole = userRole;
    }

    public String getUserCN() {
        return userCN;
    }

    public void setUserCN(String userCN) {
        this.userCN = userCN;
    }
}
