package jin.oauth2.oauth2.user;


// OAuth2 제공자 별로 OAuth2 애플리케이션과 연동 해제 하는 방법이 다릅니다.
// 서비스 별로 다른 연동 해제 방법을 통합 하기 위한 인터페이스를 정의합니다.

public interface OAuth2UserUnlink {
    void unlink(String accessToken);
}
