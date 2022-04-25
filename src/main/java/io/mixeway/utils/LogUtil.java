package io.mixeway.utils;

public class LogUtil {

    public static String prepare(String msg){
        return msg.replaceAll("[\n|\r|\t]","_");
    }
}
