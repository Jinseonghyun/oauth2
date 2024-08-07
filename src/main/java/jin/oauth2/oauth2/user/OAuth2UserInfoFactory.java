package jin.oauth2.oauth2.user;

import jin.oauth2.oauth2.exception.OAuth2AuthenticationProcessingException;

import java.util.Map;

/*
    OAuth2 인증시 액세스 토큰으로 사용자 정보를 가져왔을 때, OAuth2 제공자 별로 분기하여
    OAuth2UserInfo 인터페이스 구현체를 호출하여 OAuth2UserInfo 객체를 생성해주는 팩토리 클래스입니다.
*/

public class OAuth2UserInfoFactory {

    public static OAuth2UserInfo getOAuth2UserInfo(String registrationId,
                                                   String accessToken,
                                                   Map<String, Object> attributes) {
        if (OAuth2Provider.GOOGLE.getRegistrationId().equals(registrationId)) {
            return new GoogleOAuth2UserInfo(accessToken, attributes);
        } else if (OAuth2Provider.NAVER.getRegistrationId().equals(registrationId)) {
            return new NaverOAuth2UserInfo(accessToken, attributes);
        } else if (OAuth2Provider.KAKAO.getRegistrationId().equals(registrationId)) {
            return new KakaoOAuth2UserInfo(accessToken, attributes);
        } else {
            throw new OAuth2AuthenticationProcessingException("Login with " + registrationId + " is not supported");
        }
    }
}
