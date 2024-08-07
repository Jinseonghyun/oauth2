package jin.oauth2.oauth2;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jin.oauth2.oauth2.util.CookieUtils;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.client.web.AuthorizationRequestRepository;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

/*
    OAuth2 인증 과정중에 state, redirect_uri 등의 파라미터를 어딘가에 저장해야하는데 이를 쿠키에 저장하는 방식을 구현한 사용자 정의 클래스입니다.
    스프링 빈으로 등록하고 SecurityConfig 에서 authorizationRequestRepository 로 설정합니다.
    스프링 시큐리티 OAuth2 관련 필터인 OAuth2AuthorizationRequestRedirectFilter 와 OAuth2LoginAuthenticationFilter 에서 인증 과정중에 호출됩니다.
    최초에 프론트엔드에서 로그인 요청시 리다이렉트 할 OAuth2 제공자 별 URL 정보를 쿠키에 저장하여 리다이렉트 합니다.
    그 이후 사용자가 로그인 성공시 백엔드로 리다이렉트 될 때 인증 과정 및 사용자 정보 불러오는 과정을 마친 후 쿠키에 저장된 정보를 삭제합니다.
*/

@RequiredArgsConstructor
@Component
public class HttpCookieOAuth2AuthorizationRequestRepository
        implements AuthorizationRequestRepository<OAuth2AuthorizationRequest> {
    public static final String OAUTH2_AUTHORIZATION_REQUEST_COOKIE_NAME = "oauth2_auth_request";
    public static final String REDIRECT_URI_PARAM_COOKIE_NAME = "redirect_uri";
    public static final String MODE_PARAM_COOKIE_NAME = "mode";
    private static final int COOKIE_EXPIRE_SECONDS = 180;

    @Override
    public OAuth2AuthorizationRequest loadAuthorizationRequest(HttpServletRequest request) {
        return CookieUtils.getCookie(request, OAUTH2_AUTHORIZATION_REQUEST_COOKIE_NAME)
                .map(cookie -> CookieUtils.deserialize(cookie, OAuth2AuthorizationRequest.class))
                .orElse(null);
    }

    @Override
    public void saveAuthorizationRequest(OAuth2AuthorizationRequest authorizationRequest, HttpServletRequest request,
                                         HttpServletResponse response) {
        if (authorizationRequest == null) {
            CookieUtils.deleteCookie(request, response, OAUTH2_AUTHORIZATION_REQUEST_COOKIE_NAME);
            CookieUtils.deleteCookie(request, response, REDIRECT_URI_PARAM_COOKIE_NAME);
            CookieUtils.deleteCookie(request, response, MODE_PARAM_COOKIE_NAME);
            return;
        }

        CookieUtils.addCookie(response,
                OAUTH2_AUTHORIZATION_REQUEST_COOKIE_NAME,
                CookieUtils.serialize(authorizationRequest),
                COOKIE_EXPIRE_SECONDS);

        String redirectUriAfterLogin = request.getParameter(REDIRECT_URI_PARAM_COOKIE_NAME);
        if (StringUtils.hasText(redirectUriAfterLogin)) {
            CookieUtils.addCookie(response,
                    REDIRECT_URI_PARAM_COOKIE_NAME,
                    redirectUriAfterLogin,
                    COOKIE_EXPIRE_SECONDS);
        }

        String mode = request.getParameter(MODE_PARAM_COOKIE_NAME);
        if (StringUtils.hasText(mode)) {
            CookieUtils.addCookie(response,
                    MODE_PARAM_COOKIE_NAME,
                    mode,
                    COOKIE_EXPIRE_SECONDS);
        }
    }

    @Override
    public OAuth2AuthorizationRequest removeAuthorizationRequest(HttpServletRequest request,
                                                                 HttpServletResponse response) {
        return this.loadAuthorizationRequest(request);
    }

    public void removeAuthorizationRequestCookies(HttpServletRequest request, HttpServletResponse response) {
        CookieUtils.deleteCookie(request, response, OAUTH2_AUTHORIZATION_REQUEST_COOKIE_NAME);
        CookieUtils.deleteCookie(request, response, REDIRECT_URI_PARAM_COOKIE_NAME);
        CookieUtils.deleteCookie(request, response, MODE_PARAM_COOKIE_NAME);
    }
}
