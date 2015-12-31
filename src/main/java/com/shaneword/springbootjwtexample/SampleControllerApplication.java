package com.shaneword.springbootjwtexample;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@ComponentScan
@EnableAutoConfiguration
public class SampleControllerApplication {

    @RestController
    protected static class HomeController {
        @RequestMapping(value = "/", method = RequestMethod.GET, produces = "application/json")
        public Map<String, String> home() {
            HashMap<String,String> returnValue = new HashMap<>();
            returnValue.put("home","home");
            return returnValue;
        }
    }

    public static void main(String[] args) throws Exception {
        SpringApplication.run(SampleControllerApplication.class, args);
    }

    @Configuration
    @Order(SecurityProperties.ACCESS_OVERRIDE_ORDER)
    protected static class ApplicationSecurity extends WebSecurityConfigurerAdapter {
        @Value("${JWT_SECRET:defaultSecret}")
        protected String secret;

        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http
                .csrf().disable()
                .authorizeRequests()
                .anyRequest().authenticated().and()
                .httpBasic().and()
                .csrf().disable();
            http.addFilterBefore(new SpringSecurityJWTAuthenticationFilter(super.authenticationManagerBean()),
                    BasicAuthenticationFilter.class);
            http.addFilterAfter(new SpringSecurityAddJWTTokenFilter(jwtAuthenticationProvider()),
                    BasicAuthenticationFilter.class);
        }

        @Override
        public void configure(AuthenticationManagerBuilder auth) throws Exception {
            auth.authenticationProvider(jwtAuthenticationProvider())
                    .inMemoryAuthentication().withUser("user").password("user").roles("USER");
        }

        @Bean
        public JWTAuthenticationProvider jwtAuthenticationProvider() {
            return new JWTAuthenticationProvider(secret);
        }

    }
}
