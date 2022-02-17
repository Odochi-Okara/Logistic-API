package com.example.logisticsapi.payload.response.gen_;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class OptimalRouteAndCostResponse {

    private String optimalRoute;

    private String costOfDelivery;
}
