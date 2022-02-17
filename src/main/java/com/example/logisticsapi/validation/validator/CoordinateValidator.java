package com.example.logisticsapi.validation.validator;

import com.example.logisticsapi.validation.annotations.ValidCoordinate;


import javax.validation.ConstraintValidator;
import javax.validation.ConstraintValidatorContext;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class CoordinateValidator implements ConstraintValidator<ValidCoordinate, String> {
    @Override
    public void initialize(ValidCoordinate constraintAnnotation) {
        ConstraintValidator.super.initialize(constraintAnnotation);
    }

    @Override
    public boolean isValid(String coordinate, ConstraintValidatorContext constraintValidatorContext) {

        String regex = "-?[1-9][0-9]*(\\.[0-9]+)?,\\s*-?[1-9][0-9]*(\\.[0-9]+)?";

        Pattern pattern = Pattern.compile(regex);
        Matcher matcher = pattern.matcher(coordinate);

        return matcher.matches();
    }
}
