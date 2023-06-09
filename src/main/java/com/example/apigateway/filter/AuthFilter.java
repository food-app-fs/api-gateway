package com.example.apigateway.filter;

import com.example.apigateway.filter.RouteValidator;
import com.example.apigateway.util.JwtUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Component
public class AuthFilter extends AbstractGatewayFilterFactory<AuthFilter.Config> {

    public AuthFilter() {
        super(Config.class);
    }

    @Autowired
    JwtUtil jwtUtil;

    @Autowired
    RouteValidator routeValidator;

    @Override
    public GatewayFilter apply(Config config) {
        return (((exchange, chain) -> {

            if (routeValidator.isSecured.test(exchange.getRequest())) {

                // Check if the header contains the token
                if (!exchange.getRequest().getHeaders().containsKey(HttpHeaders.AUTHORIZATION)) {
                    return handleError(exchange, "MISSING AUTH HEADER", HttpStatus.UNAUTHORIZED);
                }

                String header = exchange.getRequest().getHeaders().get(HttpHeaders.AUTHORIZATION).get(0);

                if (header != null && header.startsWith("Bearer")) {
                    header = header.substring(7);

                    try {
                        // Validate the token
                        boolean isValidToken = jwtUtil.validateToken(header);

                        if (!isValidToken) {
                            return handleError(exchange, "INVALID TOKEN", HttpStatus.UNAUTHORIZED);
                        }
                    } catch (Exception e) {
                        Logger logger = LoggerFactory.getLogger(AuthFilter.class);
                        logger.error(e.toString());
                        return handleError(exchange, "INTERNAL SERVER ERROR", HttpStatus.INTERNAL_SERVER_ERROR);
                    }
                } else {
                    return handleError(exchange, "Invalid request", HttpStatus.BAD_REQUEST);
                }
            }

            return chain.filter(exchange);
        }));
    }

    private Mono<Void> handleError(ServerWebExchange exchange, String message, HttpStatus httpStatus) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(httpStatus);
        response.getHeaders().set(HttpHeaders.CONTENT_TYPE, "text/plain");
        return response.writeWith(Mono.just(response.bufferFactory().wrap(message.getBytes())));
    }
    public static class Config {

    }


}
