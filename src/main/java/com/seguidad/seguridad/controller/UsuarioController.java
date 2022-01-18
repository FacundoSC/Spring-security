package com.seguidad.seguridad.controller;

import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.seguidad.seguridad.entity.Usuario;
import com.seguidad.seguridad.service.UsuarioService;
import com.seguidad.seguridad.util.JwtV1Implements;
import lombok.AllArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.*;

import static com.seguidad.seguridad.util.Constants.AUTHORITIES_KEY;
import static com.seguidad.seguridad.util.Constants.TOKEN_BEARER_PREFIX;
import static java.util.Arrays.stream;
import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import static org.springframework.http.HttpStatus.FORBIDDEN;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

@RestController @RequestMapping("api") @AllArgsConstructor
@CrossOrigin
public class UsuarioController {


    private final UsuarioService userService;

    @GetMapping("/users")
    @PreAuthorize("hasRole('ROLE_USER') OR hasRole('ROLE_MANAGER')")
    public ResponseEntity<List<Usuario>> getUsers() {
        return ResponseEntity.ok().body(userService.findAll());
    }



}
