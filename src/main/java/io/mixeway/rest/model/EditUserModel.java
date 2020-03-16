package io.mixeway.rest.model;

import io.mixeway.db.entity.Project;

import java.util.List;

public class EditUserModel {
    String newPassword;
    String role;
    List<Long> projects;


    public String getRole() {
        return role;
    }

    public void setRole(String role) {
        this.role = role;
    }

    public List<Long> getProjects() {
        return projects;
    }

    public void setProjects(List<Long> projects) {
        this.projects = projects;
    }

    public String getNewPassword() {
        return newPassword;
    }

    public void setNewPassword(String newPassword) {
        this.newPassword = newPassword;
    }
}
