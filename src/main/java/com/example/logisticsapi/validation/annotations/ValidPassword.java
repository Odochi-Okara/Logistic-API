package com.example.logisticsapi.validation.annotations;

import com.example.logisticsapi.validation.validator.PasswordValidator;


import javax.validation.Constraint;
import javax.validation.Payload;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Target(ElementType.FIELD)
@Retention(RetentionPolicy.RUNTIME)
@Constraint(validatedBy = PasswordValidator.class)
public @interface ValidPassword {
    String message() default "{custom.valid.password.message}";
    Class<?>[] groups() default {};
    public abstract Class<? extends Payload>[] payload() default {};

}
