package io.mixeway.plugins.webappscan.model;

public class WebAppScanHelper {
    private final static String UUID_PATTERN = "/[a-zA-Z0-9]{8}-[a-zA-Z0-9]{4}-[a-zA-Z0-9]{4}-[a-zA-Z0-9]{4}-[a-zA-Z0-9]{12}";
    private final static String CHAR_32_PATTERN = "/[a-zA-Z0-9]{32}";
    private final static String CHAR_24_PATTERN = "/[a-zA-Z0-9]{24}";
    private final static String FOUR_DIGIT_PATTERN = "/[0-9]{4}";
    private final static String TEN_DIGIT_PATTERN = "/[0-9]{10}";
    private final static String TWELVE_DIGIT_PATTERN = "/[0-9]{12}";
    private final static String SIM_NUMBER_PATTERN = "/894803[0-9]{13}";
    private final static String MSISDN_SHORT_PATTERN = "/[0-9]{9}";
    private final static String MSISDN_LONG_PATTERN = "/[0-9]{11}";


    public static String normalizeUrl(String url) {
        String urlToLookFor = url.replaceAll("\\+","\\\\+");
        urlToLookFor=urlToLookFor.replaceAll(UUID_PATTERN,UUID_PATTERN);
        urlToLookFor=urlToLookFor.replaceAll(CHAR_32_PATTERN,CHAR_32_PATTERN);
        urlToLookFor=urlToLookFor.replaceAll(CHAR_24_PATTERN,CHAR_24_PATTERN);
        urlToLookFor=urlToLookFor.replaceAll(SIM_NUMBER_PATTERN,SIM_NUMBER_PATTERN);
        urlToLookFor=urlToLookFor.replaceAll(TWELVE_DIGIT_PATTERN,TWELVE_DIGIT_PATTERN);
        urlToLookFor=urlToLookFor.replaceAll(MSISDN_LONG_PATTERN,MSISDN_LONG_PATTERN);
        urlToLookFor=urlToLookFor.replaceAll(TEN_DIGIT_PATTERN,TEN_DIGIT_PATTERN);
        urlToLookFor=urlToLookFor.replaceAll(MSISDN_SHORT_PATTERN,MSISDN_SHORT_PATTERN);
        urlToLookFor=urlToLookFor.replaceAll(FOUR_DIGIT_PATTERN,FOUR_DIGIT_PATTERN);
        urlToLookFor= urlToLookFor.replace("?","\\?");
        urlToLookFor= urlToLookFor.replace("=","\\=");
        return urlToLookFor;
    }
}
