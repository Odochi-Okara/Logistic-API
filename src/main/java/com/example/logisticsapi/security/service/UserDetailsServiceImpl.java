package com.example.logisticsapi.security.service;


import com.example.logisticsapi.model.Staff;
import com.example.logisticsapi.repository.StaffRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import javax.transaction.Transactional;

@Service
public class UserDetailsServiceImpl implements UserDetailsService {

    private final StaffRepository userRepository;

    @Autowired
    public UserDetailsServiceImpl(StaffRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    @Transactional
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        Staff user = userRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("User with this:" + email + " not found!!!"));


        return UserDetailsImpl.build(user);
    }
}
