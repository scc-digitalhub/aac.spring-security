package it.smartcommunitylab.aac.security.authority;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.util.Assert;

public class NamespacedGrantedAuthority implements GrantedAuthority {

    private static final long serialVersionUID = -2199514268126633626L;

    private final String space;
    private final String role;

    public NamespacedGrantedAuthority(String space, String role) {
        Assert.hasText(space, "A space textual representation is required");
        Assert.hasText(role, "A granted authority textual representation is required");
        this.space = space;
        this.role = role;
    }

    public String getSpace() {
        return space;
    }

    public String getRole() {
        return role;
    }

    @Override
    public String getAuthority() {
        return space + ":" + role;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((role == null) ? 0 : role.hashCode());
        result = prime * result + ((space == null) ? 0 : space.hashCode());
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        NamespacedGrantedAuthority other = (NamespacedGrantedAuthority) obj;
        if (role == null) {
            if (other.role != null)
                return false;
        } else if (!role.equals(other.role))
            return false;
        if (space == null) {
            if (other.space != null)
                return false;
        } else if (!space.equals(other.space))
            return false;
        return true;
    }

    @Override
    public String toString() {
        return getAuthority();
    }

}
