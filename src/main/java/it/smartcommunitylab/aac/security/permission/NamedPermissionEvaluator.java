package it.smartcommunitylab.aac.security.permission;

import org.springframework.security.access.PermissionEvaluator;

public interface NamedPermissionEvaluator extends PermissionEvaluator {

    public String getName();
}
