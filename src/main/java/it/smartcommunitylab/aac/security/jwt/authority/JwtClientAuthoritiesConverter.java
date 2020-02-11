package it.smartcommunitylab.aac.security.jwt.authority;

import java.util.Collection;
import java.util.LinkedList;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

/*
 * Assign a specific role to client credentials tokens
 */
public class JwtClientAuthoritiesConverter implements Converter<Jwt, Collection<GrantedAuthority>> {

    private final String CLIENT_ROLE = "ROLE_CLIENT";
    private String clientRole;

    @Override
    public Collection<GrantedAuthority> convert(Jwt jwt) {
        Collection<GrantedAuthority> authorities = new LinkedList<>();

        // AAC specific:
        // if sub is identical to one of aud ids
        // it means that subject is a client_id
        String sub = jwt.getSubject();

        if (StringUtils.hasText(sub)) {
            if (jwt.getAudience().contains(sub)) {
                // grant client role
                authorities.add(new SimpleGrantedAuthority(getClientRole()));
            }
        }
        return authorities;
    }

    public String getClientRole() {
        if (clientRole != null) {
            return clientRole;
        } else {
            return CLIENT_ROLE;
        }
    }

    public void setClientRole(String clientRole) {
        Assert.hasText(clientRole, "client role cannot be empty");
        this.clientRole = clientRole;
    }

}
