package io.mixeway.rest.model;

import io.mixeway.db.entity.Project;

import java.util.List;

public class EditUserModel {
    String newPassword;
    String role;
    List<Project> projects;

    public String getRole() {
        return role;
    }

    public void setRole(String role) {
        this.role = role;
    }

    public List<Project> getProjects() {
        return projects;
    }

    public void setProjects(List<Project> projects) {
        this.projects = projects;
    }

    public String getNewPassword() {
        return newPassword;
    }

    public void setNewPassword(String newPassword) {
        this.newPassword = newPassword;
    }
}
