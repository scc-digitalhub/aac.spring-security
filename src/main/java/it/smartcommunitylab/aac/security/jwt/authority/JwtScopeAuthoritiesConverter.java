package it.smartcommunitylab.aac.security.jwt.authority;

import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedList;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.util.StringUtils;

import it.smartcommunitylab.aac.security.authority.ScopeGrantedAuthority;

public class JwtScopeAuthoritiesConverter implements Converter<Jwt, Collection<GrantedAuthority>> {
    private final static Logger _log = LoggerFactory.getLogger(JwtScopeAuthoritiesConverter.class);

    private final static String[] WELL_KNOWN_SCOPES_CLAIM_NAMES = { "scope", "scopes" };

    @Override
    public Collection<GrantedAuthority> convert(Jwt jwt) {
        Collection<GrantedAuthority> authorities = new LinkedList<>();

        // extract from scopes
        for (String scope : getScopes(jwt)) {
            authorities.add(new ScopeGrantedAuthority(scope));
        }
        return authorities;
    }

    private String getScopesClaimName(Jwt jwt) {
        for (String claimName : WELL_KNOWN_SCOPES_CLAIM_NAMES) {
            if (jwt.containsClaim(claimName)) {
                return claimName;
            }
        }
        return null;
    }

    @SuppressWarnings("unchecked")
    private Collection<String> getScopes(Jwt jwt) {
        String claimName = getScopesClaimName(jwt);

        if (claimName == null) {
            return Collections.emptyList();
        }

        _log.trace("extract scopes from " + claimName);

        Object scopes = jwt.getClaim(claimName);
        if (scopes instanceof String) {
            if (StringUtils.hasText((String) scopes)) {
                // the spec says the scope is separated by spaces
                return Arrays.asList(((String) scopes).split("[\\s+]"));
            } else {
                return Collections.emptyList();
            }
        } else if (scopes instanceof Collection) {
            return (Collection<String>) scopes;
        }

        return Collections.emptyList();
    }

}
