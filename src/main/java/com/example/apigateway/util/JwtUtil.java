package com.example.apigateway.util;


import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Date;

@Component
public class JwtUtil {

    //128bit key
    public static final String SECRET = "357538782F413F4428472B4B6250655368566D59703373367639792442264529";

    private Key getSignKey(){
        byte[] keyBytes = Decoders.BASE64.decode(SECRET);
        return Keys.hmacShaKeyFor(keyBytes);
    }


    public boolean validateToken(final String token) {
        try {
            Jws<Claims> claimsJws = Jwts.parserBuilder()
                    .setSigningKey(getSignKey())
                    .build()
                    .parseClaimsJws(token);

            Claims claims = claimsJws.getBody();

            // Check token expiration
            Date expirationDate = claims.getExpiration();
            Date currentDate = new Date();
            return !currentDate.after(expirationDate);
        } catch (Exception e) {
            // Handle token parsing or expiration exception
            return false;
        }
    }

}
