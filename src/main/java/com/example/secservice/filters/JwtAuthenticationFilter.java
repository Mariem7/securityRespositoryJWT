package com.example.secservice.filters;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    //object from spring security
    private AuthenticationManager authenticationManager;

    public JwtAuthenticationFilter(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    //when the user is trying to authenticate, we will retrieve the username and the password
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        System.out.println("attemptAuthentication");
        String username= request.getParameter("username");
        String password = request.getParameter("password");
        System.out.println(username);
        System.out.println(password);
        //after getting the username and password, we will return an object called usernamePasswordAuthenticationToken
        //that will get two parameters: username and the password
        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
                username,password
        );
        //we will start the operation of the authentication of this user (go to the DB and check if the user exist or not)
        return authenticationManager.authenticate(authenticationToken);
    }

    //when the user success to authenticate
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        System.out.println("successfulAuthentication");
        //we will return the authenticated user
        User user = (User)authResult.getPrincipal();
        //after getting the authenticated user, we will generate the JWT
        //secret code of crypting the signature
        Algorithm algo1 = Algorithm.HMAC256("mySecret1234");
        //aceess token
        String jwtAccessToken = JWT.create()
                .withSubject(user.getUsername())
                        .withExpiresAt(new Date(System.currentTimeMillis() +  1*60*1000)) //1 minute
                        .withIssuer(request.getRequestURL().toString()) // name of the application that created the token
                        .withClaim("roles",user.getAuthorities().stream().map(ga -> ga.getAuthority()).collect(Collectors.toList()))
                                .sign(algo1);

        //refresh token
        String jwtRefreshToken = JWT.create()
                .withSubject(user.getUsername())
                .withExpiresAt(new Date(System.currentTimeMillis() + 15*60*1000)) //15 minute
                .withIssuer(request.getRequestURL().toString()) // name of the application that created the token
                .sign(algo1);
        Map<String,String> idToken = new HashMap<>();
        idToken.put("acess-token", jwtAccessToken);
        idToken.put("refresh-token",jwtRefreshToken);
        response.setContentType("application/json");
        //we will send the two token inside the response
        new ObjectMapper().writeValue(response.getOutputStream(),idToken);
    }
}
