package com.example.logisticsapi.exception;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;

import java.time.ZoneId;
import java.time.ZonedDateTime;

@ControllerAdvice
@ResponseStatus
public class ApiExceptionHandler {

    @ExceptionHandler(value = {ApiBadRequestException.class})
    public ResponseEntity<Object> handleApiRequestException(ApiBadRequestException e) {
        HttpStatus badRequest = HttpStatus.BAD_REQUEST;

        ApiException apiException = new ApiException(e.getMessage(),
                false, badRequest, ZonedDateTime.now(ZoneId.of("Z")));

        return new ResponseEntity<>(apiException, badRequest);
    }

    @ExceptionHandler(value = {ApiResourceNotFoundException.class})
    public ResponseEntity<Object> handleApiResourceNotFoundException(ApiResourceNotFoundException e) {
        HttpStatus notFound = HttpStatus.NOT_FOUND;

        ApiException apiException = new ApiException(e.getMessage(),
                false, notFound, ZonedDateTime.now(ZoneId.of("Z")));
        

        return new ResponseEntity<>(apiException, notFound);
    }

    @ExceptionHandler(value = {ApiRequestUnauthorizedException.class})
    public ResponseEntity<Object> handleApiRequestUnauthorizedException(ApiResourceNotFoundException e) {
        HttpStatus notFound = HttpStatus.UNAUTHORIZED;

        ApiException apiException = new ApiException(e.getMessage(),
                false, notFound, ZonedDateTime.now(ZoneId.of("Z")));

        return new ResponseEntity<>(apiException, notFound);
    }


    @ExceptionHandler(value = {MethodArgumentNotValidException.class})
    public ResponseEntity<Object> customValidationErrorHandling(MethodArgumentNotValidException e){
        HttpStatus badRequest = HttpStatus.BAD_REQUEST;
        String message = e.getBindingResult().getFieldError() == null ? e.getAllErrors().get(0).getDefaultMessage() : e.getBindingResult().getFieldError().getDefaultMessage();

        ApiException apiException = new ApiException(message, false, badRequest, ZonedDateTime.now(ZoneId.of("Z")));

        return new ResponseEntity<>(apiException, badRequest);
    }

}
