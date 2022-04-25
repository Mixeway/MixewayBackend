package io.mixeway.utils;

import io.mixeway.db.entity.Project;

public class EmailVulnHelper {
    private Project project;
    private int number;
    private String result;
    private String source;
    private String color;
    private int overall;
    private String from;
    private String to;

    public int getOverall() {
        return overall;
    }

    public void setOverall(int overall) {
        this.overall = overall;
    }

    public String getFrom() {
        return from;
    }

    public void setFrom(String from) {
        this.from = from;
    }

    public String getTo() {
        return to;
    }

    public void setTo(String to) {
        this.to = to;
    }

    public Project getProject() {
        return project;
    }

    public void setProject(Project project) {
        this.project = project;
    }

    public EmailVulnHelper(Project project, int number, String result, String source, String color, String from, String to, int overall){
        this.project = project;
        this.number=number;
        this.result=result;
        this.source=source;
        this.color=color;
        this.to = to;
        this.from = from;
        this.overall = overall;
    }

    public int getNumber() {
        return number;
    }

    public void setNumber(int number) {
        this.number = number;
    }

    public String getResult() {
        return result;
    }

    public void setResult(String result) {
        this.result = result;
    }

    public String getSource() {
        return source;
    }

    public void setSource(String source) {
        this.source = source;
    }

    public String getColor() {
        return color;
    }

    public void setColor(String color) {
        this.color = color;
    }
}
