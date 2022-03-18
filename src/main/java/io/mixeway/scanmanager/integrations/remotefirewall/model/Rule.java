package io.mixeway.scanmanager.integrations.remotefirewall.model;

public class Rule {
    private String chain;
    private String num;
    private String pkts;
    private String bytes;
    private String target;
    private String prot;
    private String opt;
    private String inp;
    private String out;
    private String source;
    private String destination;
    private String extra;

    public String getChain() {
        return chain;
    }

    public void setChain(String chain) {
        this.chain = chain;
    }

    public String getNum() {
        return num;
    }

    public void setNum(String num) {
        this.num = num;
    }

    public String getPkts() {
        return pkts;
    }

    public void setPkts(String pkts) {
        this.pkts = pkts;
    }

    public String getBytes() {
        return bytes;
    }

    public void setBytes(String bytes) {
        this.bytes = bytes;
    }

    public String getTarget() {
        return target;
    }

    public void setTarget(String target) {
        this.target = target;
    }

    public String getProt() {
        return prot;
    }

    public void setProt(String prot) {
        this.prot = prot;
    }

    public String getOpt() {
        return opt;
    }

    public void setOpt(String opt) {
        this.opt = opt;
    }

    public String getInp() {
        return inp;
    }

    public void setInp(String inp) {
        this.inp = inp;
    }

    public String getOut() {
        return out;
    }

    public void setOut(String out) {
        this.out = out;
    }

    public String getSource() {
        return source;
    }

    public void setSource(String source) {
        this.source = source;
    }

    public String getDestination() {
        return destination;
    }

    public void setDestination(String destination) {
        this.destination = destination;
    }

    public String getExtra() {
        return extra;
    }

    public void setExtra(String extra) {
        this.extra = extra;
    }
}
