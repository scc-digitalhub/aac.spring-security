package it.smartcommunitylab.aac.security.jwt;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;

import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.JwtValidationException;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.util.Assert;

public class JwtValidatingDecoder implements JwtDecoder {

    private JwtDecoder jwtDecoder;
    private OAuth2TokenValidator<Jwt> jwtValidator;

    private final OAuth2TokenValidator<Jwt> defaultValidator = JwtValidators.createDefault();

    public JwtValidatingDecoder(JwtDecoder decoder) {
        Assert.notNull(decoder, "token decoder cannot be null");

        this.jwtDecoder = decoder;
        this.jwtValidator = defaultValidator;
    }

    public JwtValidatingDecoder(JwtDecoder decoder, OAuth2TokenValidator<Jwt> validator) {
        Assert.notNull(decoder, "token decoder cannot be null");
        Assert.notNull(validator, "token validator cannot be null");

        this.jwtDecoder = decoder;

        // we always want default validator included
        this.jwtValidator = new DelegatingOAuth2TokenValidator<>(defaultValidator, validator);
    }

    @SafeVarargs
    public JwtValidatingDecoder(JwtDecoder decoder, OAuth2TokenValidator<Jwt>... validators) {
        Assert.notNull(decoder, "token decoder cannot be null");

        this.jwtDecoder = decoder;

        // we always want default validator included
        Collection<OAuth2TokenValidator<Jwt>> list = new ArrayList<>();
        list.add(defaultValidator);
        list.addAll(Arrays.asList(validators));

        this.jwtValidator = new DelegatingOAuth2TokenValidator<>(list);
    }

    @Override
    public Jwt decode(String token) throws JwtException {
        Jwt jwt = jwtDecoder.decode(token);
        return validateJwt(jwt);
    }

    private Jwt validateJwt(Jwt jwt) {
        OAuth2TokenValidatorResult result = jwtValidator.validate(jwt);
        if (result.hasErrors()) {
            String description = result.getErrors().iterator().next().getDescription();
            throw new JwtValidationException(
                    String.format("An error occurred decoding and validating jwt: %s", description),
                    result.getErrors());
        }

        return jwt;
    }

}
