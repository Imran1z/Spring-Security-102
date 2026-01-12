package com.security;

import com.security.jwt.AuthEntryPoint;
import com.security.jwt.AuthTokenFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
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
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.sql.DataSource;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    @Autowired
    DataSource dataSource;

    @Bean
    public AuthTokenFilter authTokenFilter(){
        return new AuthTokenFilter();
    };

    private AuthEntryPoint authEntryPoint;

    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http){
       return http
               .csrf(customizer->customizer.disable())
               .headers(header->header.frameOptions(frame->frame.sameOrigin() ))
               .authorizeHttpRequests(req->
               req.requestMatchers("/h2-console/**").permitAll()
                       .requestMatchers("/api/login/**").permitAll()
                       .anyRequest().authenticated())
               .exceptionHandling(ex->ex.authenticationEntryPoint(authEntryPoint ))
               .sessionManagement(session-> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
               .addFilterBefore(authTokenFilter(), UsernamePasswordAuthenticationFilter.class)
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

        JdbcUserDetailsManager jdbcUserDetailsManager=new JdbcUserDetailsManager(dataSource);
        jdbcUserDetailsManager.createUser(user1);
        jdbcUserDetailsManager.createUser(user2);

        return  jdbcUserDetailsManager;

    }

    public AuthenticationManager authenticationManager(AuthenticationConfiguration builder) throws Exception{
        return builder.getAuthenticationManager();
    }
}
