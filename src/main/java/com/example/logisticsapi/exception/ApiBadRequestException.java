package com.example.logisticsapi.exception;

public class ApiBadRequestException extends RuntimeException{


    public ApiBadRequestException(String message) {
        super(message);
    }

}
