package jin.oauth2.oauth2.exception;

import org.springframework.security.core.AuthenticationException;

// OAuth2 인증 관련 실패를 위한 사용자 정의 예외 클래스입니다.

public class OAuth2AuthenticationProcessingException extends AuthenticationException {
    public OAuth2AuthenticationProcessingException(String msg) {
        super(msg);
    }
}
