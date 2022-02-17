package com.example.logisticsapi.payload.response.gen_;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.Serializable;

@AllArgsConstructor
@Data
@NoArgsConstructor
public class MessageRes implements Serializable {
    private String message;
}
