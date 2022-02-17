package com.example.logisticsapi.controller;

import com.example.logisticsapi.payload.request.location.LocationRequest;
import com.example.logisticsapi.repository.LocationRepository;
import com.example.logisticsapi.service.LocationService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RequestMapping("/api/v1/staff")
@RestController
public class LocationController {

    private LocationRepository locationRepository;

    private LocationService locationService;

    @Autowired
    public LocationController(LocationRepository locationRepository,
                           LocationService locationService) {
        this.locationRepository = locationRepository;
        this.locationService = locationService;
    }

    @PostMapping(path = "/location/add")
    public ResponseEntity<?> addNewLocation(@RequestBody LocationRequest locationRequest){
        return new ResponseEntity<>(locationService.addLocation(locationRequest), HttpStatus.CREATED);
    }

    @PutMapping(path = "/location/{locationId}/update")
    public ResponseEntity<?> updateLocation(@RequestBody LocationRequest locationRequest,
                                            @PathVariable("locationId") Long locationId){
        return new ResponseEntity<>(locationService.updateLocation(locationId, locationRequest), HttpStatus.OK);
    }

    @DeleteMapping(path = "/location/{locationId}/delete")
    public ResponseEntity<?> deleteLocation(@PathVariable("locationId") Long locationId){
        return new ResponseEntity<>(locationService.deleteLocation(locationId), HttpStatus.OK);
    }

    @GetMapping(path = "/location/generate_route_cost/{sourceId}/{destinationId}")
    public ResponseEntity<?> getOptimalRouteAndCost(@PathVariable("sourceId") Long sourceId,
                                                    @PathVariable("destinationId") Long destinationId){
        return  new ResponseEntity<>(locationService.generateOptimalRouteAndCostResponse(sourceId, destinationId), HttpStatus.OK);

    }
}
