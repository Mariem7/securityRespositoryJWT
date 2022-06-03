package com.example.secservice.services.serviceImplementations;

import com.example.secservice.entities.AppRole;
import com.example.secservice.entities.AppUser;
import com.example.secservice.repositories.AppRoleRespository;
import com.example.secservice.repositories.AppUserRepository;
import com.example.secservice.services.serviceInterfaces.AccountService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import javax.transaction.Transactional;
import java.util.List;

@Service
@Transactional
public class AccountServiceImpl implements AccountService {
    private AppUserRepository appUserRepository;
    private AppRoleRespository appRoleRespository;
    private PasswordEncoder passwordEncoder;

    //we can use @Autowired for the dependency injection
    //but for spring, it is recommanded to use constructor with 2 param
    public AccountServiceImpl(AppUserRepository appUserRepository, AppRoleRespository appRoleRespository, PasswordEncoder passwordEncoder) {
        this.appUserRepository = appUserRepository;
        this.appRoleRespository = appRoleRespository;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public AppUser addNewUser(AppUser appUser) {
        String pw=appUser.getPassword();
        appUser.setPassword(passwordEncoder.encode(pw));
        return appUserRepository.save(appUser);
    }

    @Override
    public AppRole addNewRole(AppRole appRole) {
        return appRoleRespository.save(appRole);
    }

    @Override
    public void addRoleToUser(String username, String roleName) {
        AppUser appUser = appUserRepository.findByUsername(username);
        AppRole appRole = appRoleRespository.findByRoleName(roleName);
        appUser.getAppRoles().add(appRole);
    }

    @Override
    public AppUser loadUserByUsername(String username) {
        return appUserRepository.findByUsername(username);
    }

    @Override
    public List<AppUser> listUsers() {
        return appUserRepository.findAll();
    }
}
