package com.example.logisticsapi.exception;

public class ApiResourceNotFoundException extends RuntimeException{

    public ApiResourceNotFoundException(String message) {
        super(message);
    }

}
