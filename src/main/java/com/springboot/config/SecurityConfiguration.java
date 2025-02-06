package com.springboot.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;

@Configuration
public class SecurityConfiguration {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                // H2 웹 콘솔의 화면이 <frame>태그를 사용하고 있기 때문에 정상적으로 사용할 수 있게함
                .headers().frameOptions().sameOrigin()
                .and()
                // CSRF 공격에 대한 설정 비활성화(로컬환경이기 때문에 설정하지 않으면 403에러 발생
                .csrf().disable()
                // CORS 설정 추가 default 일 경우 corsConfigurationSource 라는 이름으로 등록된 Bean 사용
                .cors(Customizer.withDefaults())
                // 폼 로그인 비활성화
                .formLogin().disable()
                // HTTP Basic 인증 방식 비활성화
                .httpBasic().disable()
                .authorizeHttpRequests(authorize ->
                        authorize.anyRequest().permitAll());
        return http.build();
    }

    // PasswordEncoder Bean 객체 생성
    @Bean
    public PasswordEncoder passwordEncoder(){
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    // CorsConfigurationSource Bean 생성을 통해 구체적인 CORS 정책 설정
    @Bean
    CorsConfigurationSource corsConfigurationSource(){
        CorsConfiguration configuration = new CorsConfiguration();
        // setAllowedOrigins : 모든 출처에 대해 허용
        configuration.setAllowedOrigins(Arrays.asList("*"));
        // setAllowedMethods : 지정한 HTTP Method 에 대한 통신 허용
        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PATCH", "DELETE"));

        // UrlBasedCorsConfigurationSource : CorsConfigurationSource의 구현체
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        // 모든 URL에 CORS 정책 적용
        source.registerCorsConfiguration("/**", configuration);

        return source;
    }
}
