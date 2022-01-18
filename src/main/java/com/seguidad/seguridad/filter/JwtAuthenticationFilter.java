package com.seguidad.seguridad.filter;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.seguidad.seguridad.util.JwtV1Implements;
import com.seguidad.seguridad.util.JwtV2Implements;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
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

import static com.seguidad.seguridad.util.Constants.*;
import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

@Slf4j
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private AuthenticationManager authenticationManager;

    public JwtAuthenticationFilter(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
           String userName = request.getParameter("username");
           String password = request.getParameter("password");
           log.info("el nombre de usuario es {}",userName);
           log.info("la contraseña es {}", password);
       /*
        try {

            AuthorizationRequest userCredentials = new ObjectMapper()
                    .readValue(request.getInputStream(), AuthorizationRequest.class);

            return authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(
                    userCredentials.getUserName(), userCredentials.getPassword()));
        } catch (IOException e) {
            return null;
        }*/

        return authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(
               userName, password));

    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        User user  = (User)authResult.getPrincipal();

        final String authorities = authResult.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(","));

        /**
         * Subject : padding
         * withIssuedAt : tiempo en milisegundos en que se hizo el token
         *with ExpiresAt : tiempo en el que expira el token
         * withIssuer ruta donde se pide el token
         */
        String token = JwtV1Implements.obtenerToken(user,authorities,request);

        //String  token2 = JwtV2Implements.obtenerToken(user,authorities,request);
        response.addHeader(AUTHORIZATION, TOKEN_BEARER_PREFIX + token);
        response.setContentType(APPLICATION_JSON_VALUE);
        Map<String, String> tokenMap = new HashMap<>();
        tokenMap.put(AUTHORIZATION,token);
        new ObjectMapper().writeValue(response.getOutputStream(),tokenMap);
    }



}
