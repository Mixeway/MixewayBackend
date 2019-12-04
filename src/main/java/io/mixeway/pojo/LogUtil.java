package io.mixeway.pojo;

public class LogUtil {

    public static String prepare(String msg){
        return msg.replaceAll("[\n|\r|\t]","_");
    }
}
