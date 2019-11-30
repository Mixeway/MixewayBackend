package io.mixeway.plugins.webappscan.model;

public class WebAppScanHelper {
    private final static String UUID_PATTERN_TO = "[a-zA-Z0-9]{8}-[a-zA-Z0-9]{4}-[a-zA-Z0-9]{4}-[a-zA-Z0-9]{4}-[a-zA-Z0-9]{12}";
    private final static String UUID_PATTERN_FROM = "[a-zA-Z0-9]{8}-[a-zA-Z0-9]{4}-[a-zA-Z0-9]{4}-[a-zA-Z0-9]{4}-[a-zA-Z0-9]{12}";
    private final static String STRANGE_PATTERN = "[a-zA-Z0-9]{32}";
    private final static String STRANGE_PATTERN1 = "[0-9]{4}";
    private final static String STRANGE_PATTERN2 = "[0-9]{10}";
    private final static String STRANGE_PATTERN3 = "[0-9]{12}";
    private final static String SIM_NUMBER_PATTERN = "894803[0-9]{13}";
    private final static String MSISDN_SHORT_PATTERN = "[0-9]{9}";
    private final static String MSISDN_LONG_PATTERN = "[0-9]{11}";


    public static String normalizeUrl(String url) {
        String urlToLookFor = url.replaceAll(UUID_PATTERN_FROM,UUID_PATTERN_TO);
        urlToLookFor=urlToLookFor.replaceAll(STRANGE_PATTERN,STRANGE_PATTERN);
        urlToLookFor=urlToLookFor.replaceAll(SIM_NUMBER_PATTERN,SIM_NUMBER_PATTERN);
        urlToLookFor=urlToLookFor.replaceAll(STRANGE_PATTERN3,STRANGE_PATTERN3);
        urlToLookFor=urlToLookFor.replaceAll(MSISDN_LONG_PATTERN,MSISDN_LONG_PATTERN);
        urlToLookFor=urlToLookFor.replaceAll(STRANGE_PATTERN2,STRANGE_PATTERN2);
        urlToLookFor=urlToLookFor.replaceAll(MSISDN_SHORT_PATTERN,MSISDN_SHORT_PATTERN);
        urlToLookFor=urlToLookFor.replaceAll(STRANGE_PATTERN1,STRANGE_PATTERN1);
        urlToLookFor= urlToLookFor.replace("?","\\?");
        urlToLookFor= urlToLookFor.replace("=","\\=");
        return urlToLookFor;
    }
}
