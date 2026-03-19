package com.example.shelldetector.exception;

public class DetectionException extends RuntimeException {
    public DetectionException(String message) {
        super(message);
    }

    public DetectionException(String message, Throwable cause) {
        super(message, cause);
    }
}
