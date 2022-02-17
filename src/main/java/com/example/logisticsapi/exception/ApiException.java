package com.example.logisticsapi.exception;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.http.HttpStatus;

import java.time.ZonedDateTime;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class ApiException {

    private String message;

    private boolean success;

    private HttpStatus httpStatus;

    private ZonedDateTime timestamp;
}
