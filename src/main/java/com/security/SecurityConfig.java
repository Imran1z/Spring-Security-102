package com.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {



    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http){
       return http.authorizeHttpRequests(req->
               req.requestMatchers("/h2-console/**").permitAll()
                       .anyRequest().authenticated())
               .sessionManagement(session-> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .httpBasic(Customizer.withDefaults()).build();
    }


    @Bean
    public UserDetailsService userDetailsService(){

        UserDetails user1 = User.withUsername("User")
                .password(passwordEncoder().encode("123"))
                .roles("USER")
                .build();

        UserDetails user2 = User.withUsername("Admin")
                .password(passwordEncoder().encode("123"))
                .roles("ADMIN")
                .build();

        return  new InMemoryUserDetailsManager(user1,user2);

    }
}
