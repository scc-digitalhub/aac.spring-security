package it.smartcommunitylab.aac.security.permission;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.access.PermissionEvaluator;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;

import it.smartcommunitylab.aac.security.authority.NamespacedGrantedAuthority;
import it.smartcommunitylab.aac.security.authority.ScopeGrantedAuthority;
import it.smartcommunitylab.aac.security.roles.DefaultRoleActionConverter;
import it.smartcommunitylab.aac.security.roles.RoleActionConverter;

@Component
public class SpacePermissionEvaluator implements PermissionEvaluator {
    private final static Logger _log = LoggerFactory.getLogger(SpacePermissionEvaluator.class);

    public final static String TARGET_TYPE = "SPACE";

    private RoleActionConverter<Namespace> roleActionConverter = new DefaultRoleActionConverter<>();

    private final List<String> spaces;

    public SpacePermissionEvaluator() {
        // enable any space
        this.spaces = Collections.singletonList("*");
    }

    public SpacePermissionEvaluator(Collection<String> spaces) {
        // restrict enabled spaces to list
        this.spaces = new ArrayList<>(spaces);
    }

    @Override
    public boolean hasPermission(Authentication authentication, Object targetDomainObject, Object permission) {
        if (!(targetDomainObject instanceof Namespace)) {
            // no space object to check
            return false;
        }

        Namespace space = (Namespace) targetDomainObject;
        String spaceId = space.getSpace();
        String userId = authentication.getName();
        String action = permission.toString();

        boolean isPermitted = isSpacePermitted(spaceId);
        _log.trace("user " + userId + " asked space " + spaceId + " permitted " + isPermitted);

        // check in Auth
        boolean hasPermission = false;

        List<GrantedAuthority> authorities = new ArrayList<>(authentication.getAuthorities());
        _log.trace("user " + userId + " authorities " + authorities.toString());

        // keep ONLY space roles

        List<String> roles = getSpaceRoles(spaceId, authorities);
        _log.trace("user " + userId + " space " + spaceId + " roles " + roles.toString());

        // append converter roles if defined
        roles.addAll(roleActionConverter.extractRoles(authentication, space));

        // get role
        List<String> allowedRoles = roleActionConverter.allowedRoles(action);
        _log.trace("user " + userId + " action " + action + " require role in " + allowedRoles.toString());

        hasPermission = CollectionUtils.containsAny(roles, allowedRoles);

//        // derive actions from roles
//        hasPermission = false;
//
//        for (String role : roles) {
//            if (roleActionConverter.toActions(role).contains(action)) {
//                hasPermission = true;
//                break;
//            }
//        }        
        _log.debug("user " + userId + " hasPermission for space " + spaceId + ":" + action + " " + hasPermission);

        return (isPermitted && hasPermission);

    }

    @Override
    public boolean hasPermission(Authentication authentication, Serializable targetId, String targetType,
            Object permission) {

        if (!TARGET_TYPE.equals(targetType)) {
            return false;
        }

        return hasPermission(authentication, new Namespace(targetId.toString()), permission);
    }

    /*
     * Helpers
     */

    public void setRoleActionConverter(RoleActionConverter<Namespace> roleActionConverter) {
        Assert.notNull(roleActionConverter, "role action converter can not be null");
        this.roleActionConverter = roleActionConverter;
    }

    public boolean isSpacePermitted(String spaceId) {

        if (spaces.contains("*")) {
            return true;
        }

        return spaces.contains(spaceId);

    }

    private List<String> getSpaceRoles(String spaceId, List<GrantedAuthority> authorities) {
        Set<String> roles = new HashSet<>();

        for (GrantedAuthority ga : authorities) {
            if (ga instanceof NamespacedGrantedAuthority) {
                NamespacedGrantedAuthority a = (NamespacedGrantedAuthority) ga;
                // require space match
                if (a.getSpace().equals(spaceId)) {
                    roles.add(a.getRole());
                }
            } else if (ga instanceof ScopeGrantedAuthority) {
                // we don't want these here
            } else {
                // any non-namespaced role is global
                roles.add(ga.getAuthority());
            }
        }

        return new ArrayList<>(roles);
    }

}
