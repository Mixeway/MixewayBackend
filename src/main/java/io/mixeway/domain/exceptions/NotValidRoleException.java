package io.mixeway.domain.exceptions;

/**
 * @author gsiewruk
 */
public class NotValidRoleException extends Exception{
    public NotValidRoleException(String errorMessage) {
        super(errorMessage);
    }
}
