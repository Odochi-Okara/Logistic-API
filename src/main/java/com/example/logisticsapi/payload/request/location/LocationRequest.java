package com.example.logisticsapi.payload.request.location;

import com.example.logisticsapi.validation.annotations.ValidCoordinate;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import javax.persistence.Column;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class LocationRequest {

    private String name;

    @ValidCoordinate(message = "The latitude value is not in the right format")
    @Column(unique=true)
    private Double latitude;

    @ValidCoordinate(message = "The longitude value is not in the right format")
    @Column(unique=true)
    private Double longitude;


}
