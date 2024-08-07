package jin.oauth2.oauth2.user;

import java.util.Map;

// OAuth2 제공자 별로 리턴하는 사용자 정보 데이터의 구조와 필드 이름 등이 다릅니다.
// (구글, 네이버, 카카오 등)서비스 별로 다른 구조를 통합하기 위한 인터페이스를 정의합니다.

public interface OAuth2UserInfo {

    OAuth2Provider getProvider();

    String getAccessToken();

    Map<String, Object> getAttributes();

    String getId();

    String getEmail();

    String getName();

    String getFirstName();

    String getLastName();

    String getNickname();

    String getProfileImageUrl();
}
