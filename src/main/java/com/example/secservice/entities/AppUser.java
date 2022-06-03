package com.example.secservice.entities;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import javax.persistence.*;
import java.util.ArrayList;
import java.util.Collection;
@Entity
@Data
@NoArgsConstructor
@AllArgsConstructor
public class AppUser {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private String username;
    //Access setting that means that the property may only be written (set) for deserialization,
    //but will not be read (get) on serialization, that is, the value of the property is not included in serialization.
    //we will ignore the password when we displayed in the json file
    @JsonProperty(access = JsonProperty.Access.WRITE_ONLY)
    private String password;
    //we need to obtain the roles of the user when we load the user
    @ManyToMany(fetch = FetchType.EAGER)
    //we have a new table in the database that will associate each user with their roles
    //when we create a user, we have to initialize the list of roles to empty list (Because of the EAGER loading)
    private Collection<AppRole> appRoles=new ArrayList<>();


}
