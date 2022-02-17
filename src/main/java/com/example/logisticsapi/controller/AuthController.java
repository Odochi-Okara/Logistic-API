package com.example.logisticsapi.controller;

import com.example.logisticsapi.dto.UserDto;
import com.example.logisticsapi.payload.request.auth.LoginRequest;
import com.example.logisticsapi.payload.request.auth.RegistrationRequest;
import com.example.logisticsapi.payload.response.auth.JwtRes;
import com.example.logisticsapi.payload.response.auth.RegistrationResponse;
import com.example.logisticsapi.service.AuthService;
import org.modelmapper.ModelMapper;
import org.modelmapper.convention.MatchingStrategies;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;

@RequestMapping("/api/v1/auth")
@RestController
public class AuthController {

    private final AuthService authService;

    @Autowired
    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    @PostMapping(path = "/register")
    public ResponseEntity<RegistrationResponse> registerUser(@Valid @RequestBody RegistrationRequest registrationReq){

        ModelMapper modelMapper =  new ModelMapper();
        modelMapper.getConfiguration().setMatchingStrategy(MatchingStrategies.STRICT);
        return new ResponseEntity<>(authService.registerUser(modelMapper.map(registrationReq, UserDto.class)), HttpStatus.CREATED);
    }

    @PostMapping("/login")
    public ResponseEntity<JwtRes> authenticateUser(@Valid @RequestBody LoginRequest loginReq) {
        return new ResponseEntity<>(authService.authenticateUser(loginReq), HttpStatus.OK);
    }


}
