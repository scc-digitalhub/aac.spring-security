package it.smartcommunitylab.aac.security.jwt;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedList;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.util.Assert;

/*
 * A composite JWT authentication converter
 */
public class JwtAuthenticationConverter implements Converter<Jwt, AbstractAuthenticationToken> {

    private Collection<Converter<Jwt, Collection<GrantedAuthority>>> authConverters;

    public JwtAuthenticationConverter() {
        authConverters = Collections.emptyList();
    }

    public JwtAuthenticationConverter(Collection<Converter<Jwt, Collection<GrantedAuthority>>> authConverters) {
        Assert.notNull(authConverters, "tokenValidators cannot be null");
        this.authConverters = new ArrayList<>(authConverters);
    }

    @SafeVarargs
    public JwtAuthenticationConverter(Converter<Jwt, Collection<GrantedAuthority>>... authConverters) {
        this(Arrays.asList(authConverters));
    }

    public void setAuthConverters(Collection<Converter<Jwt, Collection<GrantedAuthority>>> authConverters) {
        this.authConverters = new ArrayList<>(authConverters);
    }

    @Override
    public final AbstractAuthenticationToken convert(Jwt jwt) {
        Collection<GrantedAuthority> authorities = new LinkedList<>();
        for (Converter<Jwt, Collection<GrantedAuthority>> c : authConverters) {
            authorities.addAll(c.convert(jwt));
        }

        return new JwtUserAuthenticationToken(jwt, authorities);
    }
}
