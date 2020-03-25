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

import it.smartcommunitylab.aac.security.authority.SpaceGrantedAuthority;
import it.smartcommunitylab.aac.security.authority.ScopeGrantedAuthority;
import it.smartcommunitylab.aac.security.roles.DefaultRoleActionConverter;
import it.smartcommunitylab.aac.security.roles.RoleActionConverter;

@Component
public class SpacePermissionEvaluator implements NamedPermissionEvaluator {
    private final static Logger _log = LoggerFactory.getLogger(SpacePermissionEvaluator.class);

    public final static String TARGET = Space.class.getSimpleName().toUpperCase();

    private RoleActionConverter<Space> roleActionConverter = new DefaultRoleActionConverter<>();

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
        if (!(targetDomainObject instanceof Space)) {
            // no space object to check
            return false;
        }

        Space space = (Space) targetDomainObject;
        String spaceId = space.getSpace();
        String userId = authentication.getName();
        String action = permission.toString();

        boolean isPermitted = isSpacePermitted(spaceId);
        _log.trace("user " + userId + " asked space " + spaceId + " permitted " + isPermitted);

        // check in Auth
        boolean hasPermission = false;

        List<GrantedAuthority> authorities = new ArrayList<>(authentication.getAuthorities());
        _log.trace("user " + userId + " authorities " + authorities.toString());

        // get roles from space and from converter
        List<String> roles = getRoles(authentication, spaceId);
        _log.trace("user " + userId + " space " + spaceId + " roles " + roles.toString());

        // get allowed roles for action
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

        if (!TARGET.equals(targetType.toUpperCase())) {
            return false;
        }

        return hasPermission(authentication, new Space(targetId.toString()), permission);
    }

    @Override
    public String getName() {
        return TARGET;
    }

    /*
     * Helpers
     */

    public void setRoleActionConverter(RoleActionConverter<Space> roleActionConverter) {
        Assert.notNull(roleActionConverter, "role action converter can not be null");
        this.roleActionConverter = roleActionConverter;
    }

    public boolean isSpacePermitted(String spaceId) {

        if (spaces.contains("*")) {
            return true;
        }

        return spaces.contains(spaceId);

    }

    private List<String> getRoles(Authentication authentication, String spaceId) {

        // keep ONLY space roles
        List<String> roles = getSpaceRoles(new ArrayList<>(authentication.getAuthorities()), spaceId);

        // append converter roles if defined
        roles.addAll(getConverterRoles(authentication, spaceId));

        return roles;

    }

    protected List<String> getConverterRoles(Authentication authentication, String spaceId) {
        return roleActionConverter.extractRoles(authentication, new Space(spaceId));
    }

    protected List<String> getSpaceRoles(Collection<GrantedAuthority> authorities, String spaceId) {
        Set<String> roles = new HashSet<>();

        for (GrantedAuthority ga : authorities) {
            if (ga instanceof SpaceGrantedAuthority) {
                SpaceGrantedAuthority a = (SpaceGrantedAuthority) ga;
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
