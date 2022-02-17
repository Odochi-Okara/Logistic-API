package com.example.logisticsapi.service.serviceImplementation;

import com.example.logisticsapi.exception.ApiBadRequestException;
import com.example.logisticsapi.exception.ApiResourceNotFoundException;
import com.example.logisticsapi.model.Location;
import com.example.logisticsapi.payload.request.location.LocationRequest;
import com.example.logisticsapi.payload.response.gen_.MessageRes;
import com.example.logisticsapi.payload.response.gen_.OptimalRouteAndCostResponse;
import com.example.logisticsapi.repository.LocationRepository;
import com.example.logisticsapi.service.LocationService;
import org.modelmapper.ModelMapper;
import org.modelmapper.convention.MatchingStrategies;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import javax.transaction.Transactional;

@Service
public class LocationServiceImpl implements LocationService {

    private LocationRepository repository;

    @Autowired
    public LocationServiceImpl(LocationRepository repository) {
        this.repository = repository;
    }

    @Override
    public MessageRes addLocation(LocationRequest locationRequest) {

        MessageRes response = new MessageRes();

        if(isExist(locationRequest.getName(), locationRequest.getLatitude(), locationRequest.getLongitude())){
            throw new ApiBadRequestException("This location exist already!!");
        }

        Location location = Location.builder()
                .name(locationRequest.getName())
                .locationLatitude(locationRequest.getLatitude())
                .locationLongitude(locationRequest.getLongitude())
                .build();

        try {

            repository.save(location);
            response.setMessage("Location: "
                    + location.getName() + " added successfully");

        } catch (Exception exception) {
            System.out.println("Something went wrong while trying to add a location");
        }
        return response;
    }

    private Boolean isExist(String name, double lat, double log){
        return repository.existsByName(name)
                || repository.existsByLocationLatitude(lat)
                || repository.existsByLocationLongitude(log);
    }

    @Override
    @Transactional
    public MessageRes updateLocation(Long locationId, LocationRequest locationRequest) {
        var location = repository.findById(locationId)
                .orElseThrow(() -> new ApiResourceNotFoundException("Location Not found"));

        ModelMapper modelMapper = new ModelMapper();
        modelMapper.getConfiguration().setMatchingStrategy(MatchingStrategies.LOOSE);
        Location mappedLocation = modelMapper.map(locationRequest, Location.class);

        location.setName(mappedLocation.getName());
        location.setLocationLatitude(mappedLocation.getLocationLatitude());
        location.setLocationLongitude(mappedLocation.getLocationLongitude());

        return new MessageRes("Location updated successfully");
    }

    @Override
    public MessageRes deleteLocation(Long locationID) {
        MessageRes messageRes = null;
        var location = repository.findById(locationID)
                .orElseThrow(() -> new ApiResourceNotFoundException("Location Not found"));
        try {
            repository.delete(location);
             messageRes = new MessageRes("Deleted successfully");
        }catch (Exception exe){
            System.out.println("Error deleting location "+ exe.getMessage());
        }
        return messageRes;
    }

    @Override
    public OptimalRouteAndCostResponse generateOptimalRouteAndCostResponse(Long sourceId, Long destinationId) {

        double total_cost = 1.0;

        OptimalRouteAndCostResponse response = new OptimalRouteAndCostResponse();

        var sourceLocation = repository.findById(sourceId)
                .orElseThrow(()-> new ApiResourceNotFoundException("Location  not found "));

        var destinationLocation = repository.findById(destinationId)
                .orElseThrow(()-> new ApiResourceNotFoundException("Location  not found "));

        double sourceLatitude = sourceLocation.getLocationLatitude();
        double destinationLatitude = destinationLocation.getLocationLatitude();

        double sourceLongitude = sourceLocation.getLocationLongitude();
        double destinationLongitude = destinationLocation.getLocationLongitude();

        var distance =  distance(sourceLatitude, destinationLatitude, sourceLongitude, destinationLongitude, 0.0, 0.0);

        double scale = Math.pow(10, 2);
        var roundedDistance =  Math.round(distance * scale) / scale;
        var cost = total_cost * distance;
        var roundedCost =  Math.round(cost * scale) / scale;


        response.setOptimalRoute(roundedDistance + " Km");
        response.setCostOfDelivery("$ "+roundedCost);

        return  response;

    }

    private  double distance(double lat1, double lat2, double lon1,
                                  double lon2, double el1, double el2) {

        final int R = 6371; // Radius of the earth

        double latDistance = Math.toRadians(lat2 - lat1);
        double lonDistance = Math.toRadians(lon2 - lon1);
        double a = Math.sin(latDistance / 2) * Math.sin(latDistance / 2)
                + Math.cos(Math.toRadians(lat1)) * Math.cos(Math.toRadians(lat2))
                * Math.sin(lonDistance / 2) * Math.sin(lonDistance / 2);
        double c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
        double distance = R * c ;
        double height = el1 - el2;

        distance = Math.pow(distance, 2) + Math.pow(height, 2);

        return Math.sqrt(distance);
    }

}
