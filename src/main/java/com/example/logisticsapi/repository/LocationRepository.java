package com.example.logisticsapi.repository;

import com.example.logisticsapi.model.Location;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface LocationRepository extends JpaRepository<Location, Long> {

    Optional<Location> findById(Long id);

    Boolean existsByName(String name);

    Boolean existsByLocationLatitude(Double latitude);

    Boolean existsByLocationLongitude(Double longitude);

}
