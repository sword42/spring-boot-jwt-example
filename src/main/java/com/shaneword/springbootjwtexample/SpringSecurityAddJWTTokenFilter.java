package com.shaneword.springbootjwtexample;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class SpringSecurityAddJWTTokenFilter extends GenericFilterBean {
    protected JWTAuthenticationProvider jwtAuthenticationProvider;

    public SpringSecurityAddJWTTokenFilter(JWTAuthenticationProvider tJWTAuthenticationProvider) {
        jwtAuthenticationProvider = tJWTAuthenticationProvider;
    }

    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest httpRequest = (HttpServletRequest)request;
        HttpServletResponse httpResponse = (HttpServletResponse)response;
        Authentication createdAuth = SecurityContextHolder.getContext().getAuthentication();
        if (null != createdAuth && createdAuth.isAuthenticated()) {
            if (createdAuth.getPrincipal() instanceof User) {
                User theUser = (User)createdAuth.getPrincipal();
                if (null != theUser.getUsername()) {
                    String jwtToken = jwtAuthenticationProvider.createJWTToken(theUser.getUsername());
                    httpResponse.setHeader("X-AuthToken", jwtToken);
                }
            }
        }
        chain.doFilter(request, response);
    }
}
