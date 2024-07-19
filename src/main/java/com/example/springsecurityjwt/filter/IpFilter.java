package com.example.springsecurityjwt.filter;

import jakarta.persistence.SecondaryTable;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.logging.log4j.message.StringFormattedMessage;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Set;

public class IpFilter extends OncePerRequestFilter {

    private final Set<String> allowedIps = Set.of("127.0.0.1");


    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        String clientIp = request.getRemoteAddr();

        if (allowedIps.contains(clientIp)){
            filterChain.doFilter(request,response);
        } else {
            response.sendError(HttpServletResponse.SC_FORBIDDEN,"You are not allowed to access this resource");
        }

    }
}
