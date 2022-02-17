package com.example.logisticsapi.validation.annotations;

import com.example.logisticsapi.validation.validator.EmailValidator;


import javax.validation.Constraint;
import javax.validation.Payload;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Target(ElementType.FIELD)
@Retention(RetentionPolicy.RUNTIME)
@Constraint(validatedBy = EmailValidator.class)
public @interface ValidEmail {
    String message() default "{custom.valid.email.message}";
    Class<?>[] groups() default {};
    public abstract Class<? extends Payload>[] payload() default {};
}
