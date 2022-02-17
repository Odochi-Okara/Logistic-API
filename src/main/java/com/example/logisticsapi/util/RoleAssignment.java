package com.example.logisticsapi.util;


import com.example.logisticsapi.exception.ApiResourceNotFoundException;
import com.example.logisticsapi.model.Role;
import com.example.logisticsapi.model.enums.ERole;
import com.example.logisticsapi.repository.RoleRepository;
import org.springframework.stereotype.Component;

import java.util.HashSet;
import java.util.Set;

@Component
public class RoleAssignment {


    public Role assignRole(String specifiedRole, RoleRepository roleRepository) {

        Role getRole = null;

        if (specifiedRole == null || specifiedRole.toLowerCase() == "staff") {

            Role retrievedRole = roleRepository.findByName(ERole.ROLE_STAFF)
                    .orElseThrow(() -> new ApiResourceNotFoundException("No Such Role"));

            getRole = retrievedRole;

        } else if (specifiedRole.toLowerCase() == "admin") {

            Role admin = roleRepository.findByName(ERole.ROLE_ADMIN)
                    .orElseThrow(() -> new ApiResourceNotFoundException("Error: Role not found"));
            getRole = admin;
        }

        return getRole;
    }

}
