package com.example.logisticsapi.service;



import com.example.logisticsapi.payload.request.location.LocationRequest;
import com.example.logisticsapi.payload.response.gen_.MessageRes;
import com.example.logisticsapi.payload.response.gen_.OptimalRouteAndCostResponse;

public interface LocationService {

    MessageRes addLocation(LocationRequest locationRequest);

    MessageRes updateLocation(Long locationId, LocationRequest locationRequest);

    MessageRes deleteLocation(Long locationID);

    OptimalRouteAndCostResponse generateOptimalRouteAndCostResponse(Long sourceId, Long destinationId);


}
