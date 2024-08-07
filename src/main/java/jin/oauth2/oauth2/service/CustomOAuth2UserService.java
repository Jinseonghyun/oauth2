package jin.oauth2.oauth2.service;


import jin.oauth2.oauth2.exception.OAuth2AuthenticationProcessingException;
import jin.oauth2.oauth2.user.OAuth2UserInfo;
import jin.oauth2.oauth2.user.OAuth2UserInfoFactory;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

/*
    DefaultOAuth2UserService 클래스를 상속 받아 구현한 사용자 정의 클래스입니다.
    loadUser 메서드는 스프링 시큐리티 OAuth2LoginAuthenticationFilter 에서 시작된 OAuth2 인증 과정 중에 호출됩니다.
    호출되는 시점은 액세스 토큰을 OAuth2 제공자로부터 받았을 때 입니다.
*/

/*
    먼저 super.loadUser 를 통해 상위 클래스에 정의된 액세스 토큰으로 사용자 정보를 가져오는 로직을 실행해야합니다.
    그 이후 processOAuth2User 메서드를 통해 각 OAuth2 제공자 별 제공되는 사용자 정보를 동일한 인터페이스로 변환하여 리턴합니다.
*/

@RequiredArgsConstructor
@Service
public class CustomOAuth2UserService extends DefaultOAuth2UserService {

    @Override
    public OAuth2User loadUser(OAuth2UserRequest oAuth2UserRequest) throws OAuth2AuthenticationException {

        OAuth2User oAuth2User = super.loadUser(oAuth2UserRequest);

        try {
            return processOAuth2User(oAuth2UserRequest, oAuth2User);
        } catch (AuthenticationException ex) {
            throw ex;
        } catch (Exception ex) {
            // Throwing an instance of AuthenticationException will trigger the OAuth2AuthenticationFailureHandler
            throw new InternalAuthenticationServiceException(ex.getMessage(), ex.getCause());
        }
    }

    private OAuth2User processOAuth2User(OAuth2UserRequest userRequest, OAuth2User oAuth2User) {

        String registrationId = userRequest.getClientRegistration()
                .getRegistrationId();

        String accessToken = userRequest.getAccessToken().getTokenValue();

        OAuth2UserInfo oAuth2UserInfo = OAuth2UserInfoFactory.getOAuth2UserInfo(registrationId,
                accessToken,
                oAuth2User.getAttributes());

        // OAuth2UserInfo field value validation
        if (!StringUtils.hasText(oAuth2UserInfo.getEmail())) {
            throw new OAuth2AuthenticationProcessingException("Email not found from OAuth2 provider");
        }

        return new OAuth2UserPrincipal(oAuth2UserInfo);
    }
}
