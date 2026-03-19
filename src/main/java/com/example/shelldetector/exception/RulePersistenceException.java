package com.example.shelldetector.exception;

public class RulePersistenceException extends DetectionException {
    public RulePersistenceException(String message) {
        super(message);
    }

    public RulePersistenceException(String message, Throwable cause) {
        super(message, cause);
    }
}
