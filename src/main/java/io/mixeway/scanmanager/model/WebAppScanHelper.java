package io.mixeway.scanmanager.model;

public class WebAppScanHelper {
    private final static String UUID_PATTERN = "[/|+|?|&|=][a-zA-Z0-9]{8}-[a-zA-Z0-9]{4}-[a-zA-Z0-9]{4}-[a-zA-Z0-9]{4}-[a-zA-Z0-9]{12}";
    private final static String CHAR_32_PATTERN = "[/|+|?|&|=][a-zA-Z0-9]{32}";
    private final static String CHAR_24_PATTERN = "[/|+|?|&|=][a-zA-Z0-9]{24}";
    private final static String FOUR_DIGIT_PATTERN = "[/|+|?|&|=][0-9]{4}";
    private final static String THREE_DIGIT_PATTERN = "[/|+|?|&|=][0-9]{3}";
    private final static String TWO_DIGIT_PATTERN = "[/|+|?|&|=][0-9]{2}";
    private final static String FIVE_DIGIT_PATTERN = "[/|+|?|&|=][0-9]{5}";
    private final static String SIX_DIGIT_PATTERN = "[/|+|?|&|=][0-9]{6}";
    private final static String TEN_DIGIT_PATTERN = "[/|+|?|&|=][0-9]{10}";
    private final static String TWELVE_DIGIT_PATTERN = "[/|+|?|&|=][0-9]{12}";
    private final static String SIM_NUMBER_PATTERN = "[/|+|?|&|=]894803[0-9]{13}";
    private final static String MSISDN_SHORT_PATTERN = "[/|+|?|&|=][0-9]{9}";
    private final static String SEVEN_DIGIT_PATTERN = "[/|+|?|&|=][0-9]{7}";
    private final static String REFERAL_PATTERN = "[/|+|?|&|=][A-Z0-9]{10}";
    private final static String MSISDN_LONG_PATTERN = "[/|+|?|&|=][0-9]{11}";
    private final static String AT_LEAST_ONEDIGIT = "[/|+|?|&|=](?=[^/]*\\\\d)([a-zA-Z\\\\d]{24})";


    public static String normalizeUrl(String url) {
        //String urlToLookFor = url.replaceAll("+","\\\\+");
        String urlToLookFor=url.replaceAll(UUID_PATTERN,UUID_PATTERN);
        urlToLookFor= urlToLookFor.replace("?","\\?");
        urlToLookFor = urlToLookFor.replaceAll("\\+","\\\\+");
        urlToLookFor=urlToLookFor.replaceAll(CHAR_32_PATTERN,CHAR_32_PATTERN);
        urlToLookFor=urlToLookFor.replaceAll(AT_LEAST_ONEDIGIT,AT_LEAST_ONEDIGIT);
        urlToLookFor=urlToLookFor.replaceAll(CHAR_24_PATTERN,CHAR_24_PATTERN);
        urlToLookFor=urlToLookFor.replaceAll(SIM_NUMBER_PATTERN,SIM_NUMBER_PATTERN);
        urlToLookFor=urlToLookFor.replaceAll(TWELVE_DIGIT_PATTERN,TWELVE_DIGIT_PATTERN);
        urlToLookFor=urlToLookFor.replaceAll(MSISDN_LONG_PATTERN,MSISDN_LONG_PATTERN);
        urlToLookFor=urlToLookFor.replaceAll(TEN_DIGIT_PATTERN,TEN_DIGIT_PATTERN);
        urlToLookFor=urlToLookFor.replaceAll(REFERAL_PATTERN,REFERAL_PATTERN);
        urlToLookFor=urlToLookFor.replaceAll(MSISDN_SHORT_PATTERN,MSISDN_SHORT_PATTERN);
        urlToLookFor=urlToLookFor.replaceAll(SEVEN_DIGIT_PATTERN,SEVEN_DIGIT_PATTERN);
        urlToLookFor=urlToLookFor.replaceAll(SIX_DIGIT_PATTERN,SIX_DIGIT_PATTERN);
        urlToLookFor=urlToLookFor.replaceAll(FIVE_DIGIT_PATTERN,FIVE_DIGIT_PATTERN);
        urlToLookFor=urlToLookFor.replaceAll(FOUR_DIGIT_PATTERN,FOUR_DIGIT_PATTERN);
        urlToLookFor=urlToLookFor.replaceAll(THREE_DIGIT_PATTERN,THREE_DIGIT_PATTERN);
        urlToLookFor=urlToLookFor.replaceAll(TWO_DIGIT_PATTERN,TWO_DIGIT_PATTERN);

        return urlToLookFor;
    }
}
