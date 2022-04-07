/*
 * Copyright 2020-2022 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package sample.security;

import java.io.IOException;
import java.util.function.Predicate;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;

/**
 * An {@link AuthenticationSuccessHandler} for capturing the {@link OidcUser} or
 * {@link OAuth2User} for Federated Account Linking or JIT Account Provisioning.
 *
 * @author Steve Riesenberg
 * @since 0.2.3
 */
public final class FederatedIdentityAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

	private final AuthenticationSuccessHandler delegate = new SavedRequestAwareAuthenticationSuccessHandler();

	private Predicate<OAuth2User> oauth2UserTester = (user) -> false;

	private Predicate<OidcUser> oidcUserTester = (user) -> this.oauth2UserTester.test(user);

	@Override
	public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
		boolean isPrincipalInTheDb = false;
		if (authentication instanceof OAuth2AuthenticationToken) {
 			if (authentication.getPrincipal() instanceof OidcUser) {
				isPrincipalInTheDb = this.oidcUserTester.test((OidcUser) authentication.getPrincipal());
			} else if (authentication.getPrincipal() instanceof OAuth2User) {
				isPrincipalInTheDb = this.oauth2UserTester.test((OAuth2User) authentication.getPrincipal());
			}
		}

		if(isPrincipalInTheDb) {
			this.delegate.onAuthenticationSuccess(request, response, authentication);
		}
		else {
			response.sendRedirect("/register");
		}
	}

	public void setOAuth2UserHandler(Predicate<OAuth2User> oauth2UserHandler) {
		this.oauth2UserTester = oauth2UserHandler;
	}

	public void setOidcUserTester(Predicate<OidcUser> oidcUserTester) {
		this.oidcUserTester = oidcUserTester;
	}

}
