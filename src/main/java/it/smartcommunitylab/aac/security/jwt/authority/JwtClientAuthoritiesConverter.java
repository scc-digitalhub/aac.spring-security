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
    private final String CLIENT_ID_ROLE = "ROLE_CLIENT_IDENTITY";

    private String clientRole;
    private String clientIdRole;

    private String clientId;

    public JwtClientAuthoritiesConverter() {

    }

    public JwtClientAuthoritiesConverter(String clientId) {
        Assert.hasText(clientId, "A non-empty clientId is required");
        this.clientId = clientId;
    }

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

                if (StringUtils.hasText(clientId)) {
                    if (clientId.equals(sub)) {
                        // grant identity role
                        authorities.add(new SimpleGrantedAuthority(getClientIdRole()));
                    }
                }
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

    public String getClientIdRole() {
        if (clientIdRole != null) {
            return clientIdRole;
        } else {
            return CLIENT_ID_ROLE;
        }
    }

    public void setClientRole(String clientRole) {
        Assert.hasText(clientRole, "client role cannot be empty");
        this.clientRole = clientRole;
    }

    public void setClientIdRole(String clientIdRole) {
        Assert.hasText(clientIdRole, "client id role cannot be empty");
        this.clientIdRole = clientIdRole;
    }

    public void setClientId(String clientId) {
        Assert.hasText(clientId, "clientId cannot be empty");
        this.clientId = clientId;
    }
}
