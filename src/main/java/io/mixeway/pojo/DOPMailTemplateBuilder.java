package io.mixeway.pojo;

import java.util.List;

public class DOPMailTemplateBuilder {

    public String createTemplate(List<EmailVulnHelper> tools,List<EmailVulnHelper> nonprod,
                          List<EmailVulnHelper> prod,List<EmailVulnHelper> scans){
        StringBuffer sb = new StringBuffer();
        sb.append("<html>");
        sb.append("Summary report for trend in detected security vulnerability difference from <b><u>"+tools.get(0).getTo()+
                "</u></b> to <b><u>"+tools.get(0).getFrom()+"</u></b> based on automated security test suites.<br/>");
        sb.append("<h2><b>DOP - Flexible Engine - Tools</b></h2><ul>");
        for (EmailVulnHelper evh : tools){
            sb.append("<li>"+evh.getSource()+" - <font color=\""+evh.getColor()+"\"><b><u>Vulnerabilities detected: "+evh.getOverall()+"</u> [7 days trend -> "+evh.getResult()+""+evh.getNumber()+")]</b></font></li>");
        }
        sb.append("</ul><br/><h2><b>DOP - OpenWatt - NonProd</b></h2><ul>");
        for (EmailVulnHelper evh : nonprod){
            sb.append("<li>"+evh.getSource()+" - <font color=\""+evh.getColor()+"\"><b><u>Vulnerabilities detected: "+evh.getOverall()+"</u> [7 days trend -> "+evh.getResult()+""+evh.getNumber()+")]</b></font></li>");
        }
        sb.append("</ul><br/><h2><b>DOP - OpenWatt - Prod</b></h2><ul>");
        for (EmailVulnHelper evh : prod){
            sb.append("<li>"+evh.getSource()+" - <font color=\""+evh.getColor()+"\"><b><u>Vulnerabilities detected: "+evh.getOverall()+"</u> [7 days trend -> "+evh.getResult()+""+evh.getNumber()+")]</b></font></li>");
        }
        sb.append("</ul>");
        for (EmailVulnHelper evh : scans){
            sb.append("<h3>"+evh.getSource()+" - <font color=\""+evh.getColor()+"\"><b><u>Vulnerabilities detected: "+evh.getOverall()+"</u> [7 days trend -> "+evh.getResult()+""+evh.getNumber()+")]</b></font></h3>");
        }
        sb.append("</br></br>\n" +
                "* please note that this report does not contain information about newly removed vulnerabilities " +
                "(few hours back) as network, and code scanners are being launched in a scheduled manner." +
                "<br/><br/>" +
                "** Rapid changes in trend may be caused due to recently running security scan which was not yet imported. " +
                "Actual list od detected vulnerabilities is available in online mode <a href=\"https://itsec.doptools.pl/\">on ITSec website</a><br/> <br/>Message generated automatically.<br/><br/></html>");
        return sb.toString();
    }
    public String createOnlineTemplate(List<EmailVulnHelper> nonprod,List<EmailVulnHelper> prod){
        StringBuffer sb = new StringBuffer();
        sb.append("<html>");
        sb.append("Summary report for trend in detected security vulnerability difference from <b><u>"+nonprod.get(0).getTo()+
                "</u></b> to <b><u>"+nonprod.get(0).getFrom()+"</u></b> based on automated security test suites.<br/>");
        sb.append("<h2><b>Online NonProd environments (pregl)</b></h2><ul>");
        for (EmailVulnHelper evh : nonprod){
            sb.append("<li>"+evh.getSource()+" - <font color=\""+evh.getColor()+"\"><b><u>Vulnerabilities detected: "+evh.getOverall()+"</u> [7 days trend -> "+evh.getResult()+""+evh.getNumber()+")]</b></font></li>");
        }
        sb.append("</ul><br/><h2><b>Online prod </b></h2><ul>");
        for (EmailVulnHelper evh : prod){
            sb.append("<li>"+evh.getSource()+" - <font color=\""+evh.getColor()+"\"><b><u>Vulnerabilities detected: "+evh.getOverall()+"</u> [7 days trend -> "+evh.getResult()+""+evh.getNumber()+")]</b></font></li>");
        }
        sb.append("</ul>");
        sb.append("</br></br>\n" +
                "* please note that this report does not contain information about newly removed vulnerabilities " +
                "(few hours back) as network, and code scanners are being launched in a scheduled manner." +
                "<br/><br/>" +
                "** Rapid changes in trend may be caused due to recently running security scan which was not yet imported. " +
                "Actual list od detected vulnerabilities is available in online mode <a href=\"https://koordynator.corpnet.pl\">on ITSec website</a> avaliable for the administrator.<br/> <br/>Message generated automatically.<br/><br/></html>");
        return sb.toString();
    }
}
