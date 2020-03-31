package io.mixeway.pojo;

/**
 * @author gsiewruk
 */
public class ApiClientException
        extends Exception {
    public ApiClientException(String errorMessage) {
        super(errorMessage);
    }
}