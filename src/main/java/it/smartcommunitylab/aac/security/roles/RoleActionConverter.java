package it.smartcommunitylab.aac.security.roles;

import java.util.List;

public interface RoleActionConverter {

    public List<String> toRole(String action);

    public List<String> toActions(String role);
}
