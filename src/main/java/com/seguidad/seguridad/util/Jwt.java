package com.seguidad.seguridad.util;

import org.springframework.security.core.userdetails.User;

import javax.servlet.http.HttpServletRequest;

public interface Jwt {
    String obtenerToken(User user, String authorities, HttpServletRequest request);
}
