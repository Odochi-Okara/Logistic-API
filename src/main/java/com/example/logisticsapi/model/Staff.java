package com.example.logisticsapi.model;

import lombok.*;

import javax.persistence.*;


@Data
@EqualsAndHashCode(callSuper = true)
@Entity
@Table(name = "staffs")
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class Staff extends BaseModel{

    private String name;

    private String email;

    private String password;

    @OneToOne
    @Enumerated(EnumType.STRING)
    @JoinColumn(name = "role_id",referencedColumnName = "id")
    private Role role;


}
