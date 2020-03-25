package it.smartcommunitylab.aac.security.jwt.authority;

import java.util.ArrayList;
import java.util.Collection;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.util.StringUtils;

import it.smartcommunitylab.aac.security.authority.SpaceGrantedAuthority;

public class JwtComponentAwareAuthoritiesRoleConverter extends JwtSpaceAwareAuthoritiesRoleConverter {

    private final String component;

    public JwtComponentAwareAuthoritiesRoleConverter(String component) {
        super();
        this.component = component;
    }

    @Override
    public Collection<GrantedAuthority> convert(Jwt jwt) {

        // fetch from parent
        Collection<GrantedAuthority> authorities = super.convert(jwt);

        // filter if defined
        if (StringUtils.isEmpty(component)) {
            return authorities;
        } else {
            // keep only those matching and cleanup prefix
            Collection<GrantedAuthority> componentAuthorities = new ArrayList<>();
            for (GrantedAuthority authority : authorities) {
                if (authority.getAuthority().startsWith(component)) {
                    if (authority instanceof SpaceGrantedAuthority) {
                        SpaceGrantedAuthority a = (SpaceGrantedAuthority) authority;

                        String s = a.getSpace().substring(component.length());
                        if (s.startsWith("/")) {
                            // cleanup divider
                            s = s.substring(1);
                        }
                        // filter non-namespaced at component level
                        // e.g components/<component>:ROLE_PROVIDER against
                        // components/<component>/<space>:ROLE_USER
                        if (StringUtils.hasText(s)) {
                            componentAuthorities.add(new SpaceGrantedAuthority(s, a.getRole()));
                        } else {
                            // consider as top authority
                            componentAuthorities.add(new SimpleGrantedAuthority(a.getRole()));
                        }
                    } else {
                        String a = authority.getAuthority().substring(component.length());
                        componentAuthorities.add(new SimpleGrantedAuthority(a));
                    }
                }
            }

            return componentAuthorities;
        }

    }

}
