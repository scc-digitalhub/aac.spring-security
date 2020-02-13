package it.smartcommunitylab.aac.security.roles;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

import org.springframework.security.core.Authentication;
import org.springframework.util.Assert;

public class DefaultRoleActionConverter<T> implements RoleActionConverter<T> {

    public final static String ROLE = "ROLE_USER";

    private String role;

    private List<String> actions = Collections.emptyList();

    @Override
    public List<String> extractRoles(Authentication authentication, T entity) {
        return Collections.emptyList();
    }

    @Override
    public List<String> allowedRoles(String action) {
        // any action to role
        return Collections.singletonList(getRole());
    }

    @Override
    public List<String> grantsActions(String role) {
        return actions;
    }

    private String getRole() {
        if (role != null) {
            return role;
        } else {
            return ROLE;
        }
    }

    public void setRole(String role) {
        Assert.hasText(role, "role cannot be empty");
        this.role = role;
    }

    public void setAction(Collection<String> actions) {
        this.actions = new ArrayList<>(actions);
    }

}
