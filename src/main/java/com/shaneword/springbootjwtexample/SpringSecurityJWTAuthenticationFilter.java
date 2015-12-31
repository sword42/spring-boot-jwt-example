package com.shaneword.springbootjwtexample;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class SpringSecurityJWTAuthenticationFilter extends GenericFilterBean {

    protected AuthenticationManager authenticationManager;

    public SpringSecurityJWTAuthenticationFilter(AuthenticationManager  tAuthenticationManager) {
        authenticationManager = tAuthenticationManager;
    }
    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest httpRequest = (HttpServletRequest)request;
        HttpServletResponse httpResponse = (HttpServletResponse)response;
        String authHeader = httpRequest.getHeader("Authorization");
        String[] authInfo = null;
        if (null != authHeader) {
            authInfo = authHeader.split(" ");
        }
        if (null != authInfo && authInfo.length == 2 && authInfo[0].toUpperCase().startsWith("BEARER")) {
            // retrieve authentication details from request
            JWTAuthentication token = new JWTAuthentication(authInfo[1]);
            // Make sure we're authenticated
            try {
                Authentication auth = authenticationManager.authenticate(token);
                SecurityContextHolder.getContext().setAuthentication(auth);
                httpResponse.setHeader("X-AuthToken", authInfo[1]);
            } catch (Exception ex) {
                System.out.println("Exception: "+ex.getMessage());
                SecurityContextHolder.getContext().setAuthentication(null);
            }
            chain.doFilter(request, response);
            SecurityContextHolder.getContext().setAuthentication(null);
        } else {
            chain.doFilter(request, response);
        }
    }
}
