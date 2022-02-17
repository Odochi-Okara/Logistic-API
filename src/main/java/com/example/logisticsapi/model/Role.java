package com.example.logisticsapi.model;

import com.example.logisticsapi.model.enums.ERole;
import lombok.*;

import javax.persistence.*;

@Entity
@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class Role {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Enumerated(EnumType.STRING)
    private ERole name;

    public Role(ERole name){
        this.name = name;
    }
}
