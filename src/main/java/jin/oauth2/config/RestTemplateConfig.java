package jin.oauth2.config;

import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.client.RestTemplate;

// RestTemplate은 OAuth2 연결 끊기 기능 구현시 HTTP API 요청을 위해 사용합니다. RestTemplate 객체를 스프링 빈으로 등록하기 위한 설정 클래스

@Configuration
public class RestTemplateConfig {

    @Bean
    public RestTemplate restTemplate(RestTemplateBuilder restTemplateBuilder) {
        return restTemplateBuilder.build();
    }
}

