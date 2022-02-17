package com.example.logisticsapi.repository;

import com.example.logisticsapi.model.Staff;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface StaffRepository extends JpaRepository<Staff, Long> {
    Optional<Staff> findByEmail(String email);

    Boolean existsByEmail(String email);

}
