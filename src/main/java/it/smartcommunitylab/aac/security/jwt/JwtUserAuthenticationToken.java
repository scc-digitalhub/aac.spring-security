package it.smartcommunitylab.aac.security.jwt;

import java.util.Collection;
import java.util.Map;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.AbstractOAuth2TokenAuthenticationToken;

public class JwtUserAuthenticationToken extends AbstractOAuth2TokenAuthenticationToken<Jwt> {

    private static final long serialVersionUID = 8486414847513759984L;

    private final String name;
    private final String subject;
    private final String username;
    private final String email;

    /**
     * Constructs a {@code JwtAuthenticationToken} using the provided parameters.
     *
     * @param jwt the JWT
     */
    public JwtUserAuthenticationToken(Jwt jwt) {
        super(jwt);
        this.name = jwt.getSubject();
        this.subject = jwt.getSubject();
        this.username = jwt.getClaimAsString("preferred_username");
        this.email = jwt.getClaimAsString("email");
    }

    /**
     * Constructs a {@code JwtAuthenticationToken} using the provided parameters.
     *
     * @param jwt         the JWT
     * @param authorities the authorities assigned to the JWT
     */
    public JwtUserAuthenticationToken(Jwt jwt, Collection<? extends GrantedAuthority> authorities) {
        super(jwt, authorities);
        this.setAuthenticated(true);
        this.name = jwt.getSubject();
        this.subject = jwt.getSubject();
        this.username = jwt.getClaimAsString("preferred_username");
        this.email = jwt.getClaimAsString("email");
    }

    /**
     * Constructs a {@code JwtAuthenticationToken} using the provided parameters.
     *
     * @param jwt         the JWT
     * @param authorities the authorities assigned to the JWT
     * @param name        the principal name
     */
    public JwtUserAuthenticationToken(Jwt jwt, Collection<? extends GrantedAuthority> authorities, String name) {
        super(jwt, authorities);
        this.setAuthenticated(true);
        this.name = name;
        this.subject = jwt.getSubject();
        this.username = jwt.getClaimAsString("preferred_username");
        this.email = jwt.getClaimAsString("email");
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Map<String, Object> getTokenAttributes() {
        return this.getToken().getClaims();
    }

    @Override
    public String getName() {
        return this.name;
    }

    public String getSubject() {
        return subject;
    }

    public String getUsername() {
        return username;
    }

    public String getEmail() {
        return email;
    }

}
