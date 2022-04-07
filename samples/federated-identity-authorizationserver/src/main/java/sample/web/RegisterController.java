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
package sample.web;

import java.io.IOException;

import javax.servlet.http.HttpServletResponse;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import sample.security.UserRepositoryOAuth2UserHandler;

/**
 * @author Steve Riesenberg
 * @since 0.2.3
 */
@Controller
public class RegisterController {

	private final UserRepositoryOAuth2UserHandler userHandler;

	public RegisterController(UserRepositoryOAuth2UserHandler userHandler) {
		this.userHandler = userHandler;
	}

	@GetMapping("/register")
	public String register() {
		return "register";
	}

	@PostMapping("/register")
	public String register(@RequestParam(value = "create") boolean create, Authentication authn, HttpServletResponse response)
			throws IOException {
		if (authn instanceof OAuth2AuthenticationToken) {
			OAuth2AuthenticationToken accessToken = (OAuth2AuthenticationToken) authn;
			String idp = accessToken.getAuthorizedClientRegistrationId();

			// save the user in the db:
			if (!userHandler.test(accessToken.getPrincipal())) {
				userHandler.accept(accessToken.getPrincipal());
			}

			response.sendRedirect("/oauth2/authorization/" + idp);
		}
		return "register";
	}
}
