package io.mixeway.pojo;

public class NetworkService {
    String netProto;
    String appProto;
    int port;
    String status;
    String name;

    public String getNetProto() {
        return netProto;
    }

    public void setNetProto(String netProto) {
        this.netProto = netProto;
    }

    public String getAppProto() {
        return appProto;
    }

    public void setAppProto(String appProto) {
        this.appProto = appProto;
    }

    public int getPort() {
        return port;
    }

    public void setPort(int port) {
        this.port = port;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }
}
