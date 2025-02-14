package com.mesutpiskin.keycloak.auth.email;

import static com.mesutpiskin.keycloak.auth.email.ConditionalEmailAuthenticatorForm.OtpDecision.SHOW_OTP;
import static com.mesutpiskin.keycloak.auth.email.ConditionalEmailAuthenticatorForm.OtpDecision.SKIP_OTP;
import static org.keycloak.models.utils.KeycloakModelUtils.getRoleFromString;

import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.UserModel;

public class ConditionalEmailAuthenticatorForm extends EmailAuthenticatorForm {

    public static final String SKIP_OTP_ROLE = "skipOtpRole";

    enum OtpDecision {
        SKIP_OTP, SHOW_OTP
    }
	
	@Override
    public void authenticate(AuthenticationFlowContext context) {
        if (tryConcludeBasedOn(voteForUserRole(context.getRealm(), context.getUser()), context)) {
            return;
        }

        showOtpForm(context);
    }

    private boolean tryConcludeBasedOn(OtpDecision state, AuthenticationFlowContext context) {

        switch (state) {

            case SHOW_OTP:
                showOtpForm(context);
                return true;

            case SKIP_OTP:
                context.success();
                return true;

            default:
                return false;
        }
    }

    private void showOtpForm(AuthenticationFlowContext context) {
        super.authenticate(context);
    }

    private OtpDecision voteForUserRole(RealmModel realm, UserModel user) {
        if (userHasRole(realm, user, SKIP_OTP_ROLE)) {
            return SKIP_OTP;
        }

        return SHOW_OTP;
    }

    private boolean userHasRole(RealmModel realm, UserModel user, String roleName) {

        if (roleName == null) {
            return false;
        }

        RoleModel role = getRoleFromString(realm, roleName);
        if (role != null) {
            return user.hasRole(role);
        }
        return false;
    }
}
