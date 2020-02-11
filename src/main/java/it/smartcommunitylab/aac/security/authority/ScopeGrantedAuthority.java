package it.smartcommunitylab.aac.security.authority;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.util.Assert;

public class ScopeGrantedAuthority implements GrantedAuthority {

    private static final long serialVersionUID = -663178281706217411L;

    private final String scope;

    public ScopeGrantedAuthority(String scope) {
        Assert.hasText(scope, "A scope textual representation is required");
        this.scope = scope;
    }

    public String getScope() {
        return scope;
    }

    @Override
    public String getAuthority() {
        return "SCOPE_" + scope;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((scope == null) ? 0 : scope.hashCode());
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
        ScopeGrantedAuthority other = (ScopeGrantedAuthority) obj;
        if (scope == null) {
            if (other.scope != null)
                return false;
        } else if (!scope.equals(other.scope))
            return false;
        return true;
    }

    @Override
    public String toString() {
        return getAuthority();
    }

}
