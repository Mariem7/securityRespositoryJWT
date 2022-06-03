package com.example.secservice.controllers;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.example.secservice.entities.AppRole;
import com.example.secservice.entities.AppUser;
import com.example.secservice.services.serviceInterfaces.AccountService;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.Data;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.file.Path;
import java.util.*;
import java.util.stream.Collectors;

@RestController
public class AccountRestController {
    private AccountService accountService;

    public AccountRestController(AccountService accountService) {
        this.accountService = accountService;
    }

    @GetMapping(path ="/users")
    @PostAuthorize("hasAuthority('USER')")
    public List<AppUser> appUsers(){
        return accountService.listUsers();
    }

    @PostMapping(path = "/users")
    @PostAuthorize("hasAuthority('ADMIN')")
    public AppUser saveUser(@RequestBody AppUser appUser){
        return accountService.addNewUser(appUser);
    }

    @PostMapping(path = "/roles")
    @PostAuthorize("hasAuthority('ADMIN')")
    public AppRole saveRole(@RequestBody AppRole appRole){
        return accountService.addNewRole(appRole);
    }

    @PostMapping(path = "/addRoleToUser")
        public void addRoleToUser(@RequestBody RoleUserForm roleUserForm){
         accountService.addRoleToUser(roleUserForm.getUsername(),roleUserForm.getRoleName());
    }
    @GetMapping(path="/refreshToken")
    public void refreshToken(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String auhToken=request.getHeader("Authorization");
        if(auhToken!=null && auhToken.startsWith("Bearer ")){
            try {
                String jwtRefreshToken= auhToken.substring(7);
                //for decrypting the token
                Algorithm algorithm = Algorithm.HMAC256("mySecret1234");
                //creating the token
                JWTVerifier jwtVerifier = JWT.require(algorithm).build();
                //verifing the token (expired or not...)
                DecodedJWT decodedJWT = jwtVerifier.verify(jwtRefreshToken);
                //retrieve the username
                String username= decodedJWT.getSubject();
                AppUser appUser = accountService.loadUserByUsername(username);
                //aceess token
                String jwtAccessToken = JWT.create()
                        .withSubject(appUser.getUsername())
                        .withExpiresAt(new Date(System.currentTimeMillis() +  1*60*1000)) //1 minute
                        .withIssuer(request.getRequestURL().toString()) // name of the application that created the token
                        .withClaim("roles",appUser.getAppRoles().stream().map(ga -> ga.getRoleName()).collect(Collectors.toList()))
                        .sign(algorithm);
                Map<String,String> idToken = new HashMap<>();
                idToken.put("acess-token", jwtAccessToken);
                idToken.put("refresh-token",jwtRefreshToken);
                response.setContentType("application/json");
                //we will send the two token inside the response
                new ObjectMapper().writeValue(response.getOutputStream(),idToken);
            }catch (Exception e){
                throw e;
            }
        }else{
            throw new RuntimeException("Refresh token required");
        }
    }
}


@Data
class RoleUserForm{
    private String username;
    private String roleName;
}