package it.smartcommunitylab.aac.security.roles;

import java.util.List;

import org.springframework.security.core.Authentication;

public interface RoleActionConverter<T> {

    public List<String> extractRoles(Authentication authentication, T entity);

    public List<String> allowedRoles(String action);

    public List<String> grantsActions(String role);
}
