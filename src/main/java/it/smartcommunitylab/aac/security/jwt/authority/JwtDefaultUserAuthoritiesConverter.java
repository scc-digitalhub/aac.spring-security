package it.smartcommunitylab.aac.security.jwt.authority;

import java.util.Collection;
import java.util.LinkedList;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.util.Assert;

/*
 * Assign to any authorized user the default role
 */
public class JwtDefaultUserAuthoritiesConverter implements Converter<Jwt, Collection<GrantedAuthority>> {

    private final String DEFAULT_ROLE = "ROLE_USER";
    private String defaultRole;

    @Override
    public Collection<GrantedAuthority> convert(Jwt jwt) {
        Collection<GrantedAuthority> authorities = new LinkedList<>();

        // grant default role to any authenticated user
        authorities.add(new SimpleGrantedAuthority(getDefaultRole()));

        return authorities;
    }

    public String getDefaultRole() {
        if (defaultRole != null) {
            return defaultRole;
        } else {
            return DEFAULT_ROLE;
        }
    }

    public void setDefaultRole(String defaultRole) {
        Assert.hasText(defaultRole, "default role cannot be empty");
        this.defaultRole = defaultRole;
    }

}
