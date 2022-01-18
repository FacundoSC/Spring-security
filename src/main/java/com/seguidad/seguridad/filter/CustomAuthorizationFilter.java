package com.seguidad.seguridad.filter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.seguidad.seguridad.service.UsuarioService;
import com.seguidad.seguridad.util.JwtV1Implements;
import com.seguidad.seguridad.util.JwtV2Implements;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

import static com.seguidad.seguridad.util.Constants.*;
import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import static org.springframework.http.HttpStatus.FORBIDDEN;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

@Slf4j

public class CustomAuthorizationFilter extends OncePerRequestFilter {
    @Autowired
    private  UsuarioService usuarioService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        if(request.getRequestURL().equals(REQUEST_TOKEN_URL)){
            filterChain.doFilter(request,response);
        }
        else{
            String authorizationHeader = request.getHeader(AUTHORIZATION);
                if (authorizationHeader != null && authorizationHeader.startsWith(TOKEN_BEARER_PREFIX)) {
                     try{
                          String token = authorizationHeader.substring(TOKEN_BEARER_PREFIX.length());
                          DecodedJWT decodedJWT = JwtV1Implements.getJwtVerifier(token);
                          String userName = JwtV1Implements.getUserName(decodedJWT); //JwtV2Implements.getUserName(token);
                          UserDetails user = usuarioService.loadUserByUsername(userName);
                          UsernamePasswordAuthenticationToken authenticationToken = JwtV1Implements.getAuthentication(decodedJWT,user);
                          SecurityContextHolder.getContext().setAuthentication(authenticationToken);
                          filterChain.doFilter(request, response);
                      }
                      catch(Exception e){
                         log.info("error Authentic login : {}", e.getMessage());
                         response.setHeader("error", e.getMessage());
                         response.setStatus(FORBIDDEN.value());
                         response.setContentType(APPLICATION_JSON_VALUE);
                         Map<String, String> error = new HashMap<>();
                         error.put("error_message", e.getMessage());
                          new ObjectMapper().writeValue(response.getOutputStream(), error);
                      }
                }
                else{
                    // resolver en caso de no tener la cabecera
                    filterChain.doFilter(request, response);
                }

        }

            
    }

}
