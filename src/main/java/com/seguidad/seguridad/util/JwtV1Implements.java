package com.seguidad.seguridad.util;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import lombok.NoArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;

import javax.servlet.http.HttpServletRequest;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;

import static com.seguidad.seguridad.util.Constants.*;
import static java.util.Arrays.stream;

@NoArgsConstructor
public class JwtV1Implements  {

    public static String obtenerToken(User user, String authorities, HttpServletRequest request){
        Algorithm alg = Algorithm.HMAC256(SIGNING_KEY);

        String token = JWT.create().withSubject(user.getUsername()).withIssuedAt(new Date(System.currentTimeMillis()))
                .withClaim(AUTHORITIES_KEY,authorities)
                .withExpiresAt(new Date(System.currentTimeMillis() + ACCESS_TOKEN_VALIDITY_SECONDS*1000))
                .withIssuer(request.getRequestURL().toString()).sign(alg);

        return token;

    }

    public static UsernamePasswordAuthenticationToken getAuthentication(DecodedJWT decodedJWT, UserDetails userDetails) {
        String[] roles = decodedJWT.getClaim(AUTHORITIES_KEY).asString().split(" ");
        Collection<SimpleGrantedAuthority> authoridades = new ArrayList<>();
        stream(roles).forEach(role -> authoridades.add(new SimpleGrantedAuthority(role)));
        return new UsernamePasswordAuthenticationToken(userDetails, null, authoridades);
    }

    public static String getUserName(final DecodedJWT decodedJWT ) {;
        String userName = decodedJWT.getSubject();
        return userName;
    }


    public static DecodedJWT getJwtVerifier(final String token){
        Algorithm alg = Algorithm.HMAC256(SIGNING_KEY);
        JWTVerifier jwtVerifier = JWT.require(alg).build();
        return jwtVerifier.verify(token);
    }


}
