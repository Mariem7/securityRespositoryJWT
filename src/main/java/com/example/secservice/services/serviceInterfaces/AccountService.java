package com.example.secservice.services.serviceInterfaces;

import com.example.secservice.entities.AppRole;
import com.example.secservice.entities.AppUser;

import java.util.List;


public interface AccountService {
    AppUser addNewUser(AppUser appUser);
    AppRole addNewRole(AppRole appRole);
    void addRoleToUser(String username, String roleName);
    AppUser loadUserByUsername(String username);
    List<AppUser> listUsers();

}
