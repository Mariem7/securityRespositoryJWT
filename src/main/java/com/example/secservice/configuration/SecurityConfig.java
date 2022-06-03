package com.example.secservice.configuration;

import com.example.secservice.entities.AppUser;
import com.example.secservice.filters.JwtAuthenticationFilter;
import com.example.secservice.filters.JwtAuthorizationFilter;
import com.example.secservice.services.serviceInterfaces.AccountService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.util.ArrayList;
import java.util.Collection;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter{
    @Autowired
    private AccountService accountService;

    //users who has the authoritie to access the application
    //how spring security will fetch the users and theirs roles
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        //fetch users
        auth.userDetailsService(new UserDetailsService() {
            @Override
            public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
                AppUser appUser = accountService.loadUserByUsername(username);
                //convert roles to GrantedAuthorities
                Collection<GrantedAuthority> authorities = new ArrayList<>();
                appUser.getAppRoles().forEach( r->{
                            authorities.add(new SimpleGrantedAuthority(r.getRoleName()));
                        }
                );
                return new User(appUser.getUsername(), appUser.getPassword(),authorities);
            }
        });
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        //when we use JWT, we use authentication stateless so we don't need the csrf protection
        //we use csrf only in statefull authentication (when we use cookies)
        http.csrf().disable();
        //we are not going to generate the session on server side, but it will be generated inside the JWT
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
        //to display the frames of the H2 Database
        http.headers().frameOptions().disable();
        http.authorizeRequests().antMatchers("/h2-console/**","/refreshToken/**","/login/**").permitAll();
        //http.authorizeRequests().antMatchers(HttpMethod.POST,"/users/**").hasAuthority("ADMIN");
        //http.authorizeRequests().antMatchers(HttpMethod.GET,"/users/**").hasAuthority("USER");
        http.authorizeRequests().anyRequest().authenticated();
        http.addFilter(new JwtAuthenticationFilter(authenticationManagerBean()));
        //giving the type of the filter
        http.addFilterBefore(new JwtAuthorizationFilter(), UsernamePasswordAuthenticationFilter.class);
    }
    @Bean
    @Override
    //we need to call the authentication manager because the jwtAuthenticationFilter need an authenticationManager object
    public AuthenticationManager authenticationManagerBean() throws Exception{
        return super.authenticationManagerBean();
    }
}
