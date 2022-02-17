package com.example.logisticsapi.util;


import com.example.logisticsapi.model.Role;
import com.example.logisticsapi.model.enums.ERole;
import com.example.logisticsapi.repository.RoleRepository;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.Optional;


@Service
public class DatabaseSeeding {

    private final Logger logger = LoggerFactory.getLogger(this.getClass());

    private static RoleRepository roleRepository = null;

    public DatabaseSeeding(RoleRepository roleRepository) {
        this.roleRepository = roleRepository;
    }

    public void seed() {
        try {

            seedAdminRole();
            seedUserRole();


        } catch (Exception exception) {
            exception.printStackTrace();
        }

    }

    private void seedUserRole() {
        Role user = Role.builder()
                .name(ERole.ROLE_STAFF)
                .build();

        Optional<Role> role = roleRepository.findByName(ERole.ROLE_STAFF);
        if(role.isEmpty()) {
            roleRepository.save(user);
        }

    }

    private void seedAdminRole() {
        Role admin = Role.builder()
                .name(ERole.ROLE_ADMIN)
                .build();

        Optional<Role> role = roleRepository.findByName(ERole.ROLE_ADMIN);
        if(role.isEmpty()) {
            roleRepository.save(admin);
        }
    }

}
