package io.mixeway.utils;

import java.util.List;

public class DOPMailTemplateBuilder {

    public String createTemplateEmail(List<List<EmailVulnHelper>> vulns){
        StringBuffer sb = new StringBuffer();
        sb.append("<html>");
        sb.append("Summary report for trend in detected security vulnerability difference from <b><u>"+vulns.get(0).get(0).getTo()+
                "</u></b> to <b><u>"+vulns.get(0).get(0).getFrom()+"</u></b> based on automated security test suites.<br/>");
        for (List<EmailVulnHelper> vulnHelpers : vulns) {
            sb.append("<h2><b>" + vulnHelpers.get(0).getProject().getName() + "</b></h2><ul>");
            for (EmailVulnHelper evh : vulnHelpers) {
                sb.append("<li>" + evh.getSource() + " - <font color=\"" + evh.getColor() + "\"><b><u>Vulnerabilities detected: " + evh.getOverall() + "</u> [7 days trend -> " + evh.getResult() + "" + evh.getNumber() + ")]</b></font></li>");
            }
            sb.append("</ul>");
        }
        sb.append("</br></br>\n" +
                "* please note that this report does not contain information about newly removed vulnerabilities " +
                "(few hours back) as network, and code scanners are being launched in a scheduled manner." +
                "<br/><br/>" +
                "** Rapid changes in trend may be caused due to recently running security scan which was not yet imported. " +
                "<br/> <br/>Message generated automatically.<br/><br/></html>");
        return sb.toString();
    }

}
