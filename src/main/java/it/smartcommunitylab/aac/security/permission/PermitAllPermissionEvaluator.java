package it.smartcommunitylab.aac.security.permission;

import java.io.Serializable;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.access.PermissionEvaluator;
import org.springframework.security.core.Authentication;

public class PermitAllPermissionEvaluator implements PermissionEvaluator {

    private final static Logger _log = LoggerFactory.getLogger(PermitAllPermissionEvaluator.class);

    /**
     * @return true always
     */
    public boolean hasPermission(Authentication authentication, Object target,
            Object permission) {
        _log.warn("Allowing user " + authentication.getName() + " permission '"
                + permission + "' on object " + target);
        return true;
    }

    /**
     * @return true always
     */
    public boolean hasPermission(Authentication authentication, Serializable targetId,
            String targetType, Object permission) {
        _log.warn("Allowing user " + authentication.getName() + " permission '"
                + permission + "' on object with Id '" + targetId);
        return true;
    }
}