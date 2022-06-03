package com.example.secservice.filters;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;

public class JwtAuthorizationFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        if(request.getServletPath().equals("/refreshToken")){
            filterChain.doFilter(request,response);
        }else{
            String authorizationToken= request.getHeader("Authorization");
            if(authorizationToken!= null && authorizationToken.startsWith("Bearer ")){
                try {
                    String jwt= authorizationToken.substring(7);
                    //for decrypting the token
                    Algorithm algorithm = Algorithm.HMAC256("mySecret1234");
                    //creating the token
                    JWTVerifier jwtVerifier = JWT.require(algorithm).build();
                    //verifing the token (expired or not...)
                    DecodedJWT decodedJWT = jwtVerifier.verify(jwt);
                    //retrieve the username
                    String username= decodedJWT.getSubject();
                    //retieve the roles
                    String[] roles = decodedJWT.getClaim("roles").asArray(String.class);
                    Collection<GrantedAuthority> authorities = new ArrayList<>();
                    for(String r:roles){
                        authorities.add(new SimpleGrantedAuthority(r));
                    }
                    UsernamePasswordAuthenticationToken authenticationToken =
                            new UsernamePasswordAuthenticationToken(username,null,authorities);
                    //we will authenticate this user
                    SecurityContextHolder.getContext().setAuthentication(authenticationToken);
                    //passing this request to the next filter
                    filterChain.doFilter(request,response);
                }catch (Exception e){
                    response.setHeader("error-message",e.getMessage());
                    response.sendError(HttpServletResponse.SC_FORBIDDEN);
                }
            }else{
                filterChain.doFilter(request,response);
            }
        }

    }
}
