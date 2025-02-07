package com.springboot.config;

import com.springboot.auth.filter.JwtAuthenticationFilter;
import com.springboot.auth.filter.JwtVerificationFilter;
import com.springboot.auth.handler.MemberAccessDeniedHandler;
import com.springboot.auth.handler.MemberAuthenticationEntryPoint;
import com.springboot.auth.handler.MemberAuthenticationFailureHandler;
import com.springboot.auth.handler.MemberAuthenticationSuccessHandler;
import com.springboot.auth.jwt.JwtTokenizer;
import com.springboot.auth.utils.AuthorityUtils;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;

@Configuration
public class SecurityConfiguration {
    private final JwtTokenizer jwtTokenizer;
    private final AuthorityUtils authorityUtils;

    public SecurityConfiguration(JwtTokenizer jwtTokenizer, AuthorityUtils authorityUtils) {
        this.jwtTokenizer = jwtTokenizer;
        this.authorityUtils = authorityUtils;
    }

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
                // 세션을 생성하지 않도록 설정
                // ALWAYS : 항상 생성
                // NEVER : 생성은 x, 이미 생성된 세션있으면 사용
                // IF_REQUIRED : 필요한 경우에만 생성
                // STATELESS : 세션 생성 x - SecurityContext 정보를 얻기 위해 절대 안씀.
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                // 폼 로그인 비활성화
                .formLogin().disable()
                // HTTP Basic 인증 방식 비활성화
                .httpBasic().disable()
                .exceptionHandling()
                // 인증 실패 시 처리하는 EntryPoint 설정
                // 인증되지 않은 사용자가 보호된 리소스에 접근하려고 할 때 호출됨
                .authenticationEntryPoint(new MemberAuthenticationEntryPoint())
                // 인가 실패 시 처리하는 핸들러 설정
                // 인증된 사용자가 권한이 없는 리소스에 접근하려고 할 때 호출됨
                .accessDeniedHandler(new MemberAccessDeniedHandler())
                .and()
                // Custom Configurer : Spring Security의 Configuration을 개발자 입맛에 맞게 정의할 수 있는 기능
                .apply(new CustomFilterConfigurer())
                .and()
                // 접근 권한에 따른 리소스 접근 설정
                .authorizeHttpRequests(authorize -> authorize
                        // HTTP 각 메서드의 핸들러 메서드에 대한 접근 권한 부여 설정임
                        // '**'은 하위 URL로 어떤 URL이 오더라도 매치 됨.
                        // 회원 등록은 누구나 가능
                        .antMatchers(HttpMethod.POST, "/*/members").permitAll()
                        // 회원 정보 수정은 user만
                        .antMatchers(HttpMethod.PATCH, "/*/members/**").hasRole("USER")
                        // 모든 회원 목록은 관리자만
                        .antMatchers(HttpMethod.GET, "/*/members").hasRole("ADMIN")
                        // 특정 회원 정보 조회는 모두 접근(비회원 불가)
                        .antMatchers(HttpMethod.GET, "/*/members/**").hasAnyRole("USER", "ADMIn")
                        // 삭제 요청은 user만
                        .antMatchers(HttpMethod.DELETE, "/*/members/**").hasRole("USER")
                        // 커피 등록은 관리자만 ----------
                        .antMatchers(HttpMethod.POST, "/*/coffees").hasRole("ADMIN")
                        // 커피 정보 수정은 관리자만
                        .antMatchers(HttpMethod.PATCH, "/*/coffees/**").hasRole("ADMIN")
                        // 모든 커피 목록은 모두 접근
                        .antMatchers(HttpMethod.GET, "/*/coffees").permitAll()
                        // 커피 정보 조회는 모두 접근
                        .antMatchers(HttpMethod.GET, "/*/coffees/**").permitAll()
                        // 삭제 요청은 관리자만
                        .antMatchers(HttpMethod.DELETE, "/*/coffees/**").hasRole("ADMIN")
                        // 주문 등록은 유저만 ----------
                        .antMatchers(HttpMethod.POST, "/*/orders").hasRole("USER")
                        // 주문 정보 수정은 유저
                        .antMatchers(HttpMethod.PATCH, "/*/orders/**").hasRole("USER")
                        // 모든 주문 목록은 모두 접근( 대신 user는 본인 주문 목록만 나오게)
                        .antMatchers(HttpMethod.GET, "/*/orders").permitAll()
                        // 주문 정보 조회는 모두 접근
                        .antMatchers(HttpMethod.GET, "/*/orders/**").hasAnyRole("USER", "ADMIN")
                        // 삭제 요청은 유저만
                        .antMatchers(HttpMethod.DELETE, "/*/orders/**").hasRole("USER")

                        // .anyRequest().permitAll()) 이거는 무조건 맨 마지막에 해야함 안그러면 필터링이 안됨
                        .anyRequest().permitAll());
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

    // 구현한 JwtAuthenticationFilter 를 등록하는 역할
    // AbstractHttpConfigurer 를 상속
    // AbstractHttpConfigurer를 상속하는 타입과 HttpSecurityBuilder를 상속하는 타입을 제너릭 타입으로 지정할 수 있음
    public class CustomFilterConfigurer extends AbstractHttpConfigurer<CustomFilterConfigurer, HttpSecurity>{
        // configure() 메서드를 오버라이드해서 Configuration을 커스터마이징
        @Override
        public void configure(HttpSecurity builder) throws Exception {
            // getSharedObject() : Spring Security의 설정을 구성하는 SecurityConfigurer 간에 공유되는 객체 가져올 수 있음
            // AuthenticationManager 의 객체 가져옴
            AuthenticationManager authenticationManager = builder.getSharedObject(AuthenticationManager.class);

            // JwtAuthenticationFilter를 생성하면서
            // JwtAuthenticationFilter에서 사용되는 AuthenticationManager와 JwtTokenizer를 DI
            JwtAuthenticationFilter jwtAuthenticationFilter = new JwtAuthenticationFilter(authenticationManager, jwtTokenizer);
            // setFilterProcessesUrl() 메서드를 통해 디폴트 request URL인 “/login”을 “/v11/auth/login”으로 변경
            jwtAuthenticationFilter.setFilterProcessesUrl("/v11/auth/login");

            // success handler 등록
            jwtAuthenticationFilter.setAuthenticationSuccessHandler(new MemberAuthenticationSuccessHandler());
            // failure handler 등록
            jwtAuthenticationFilter.setAuthenticationFailureHandler(new MemberAuthenticationFailureHandler());

            //  JwtVerificationFilter의 인스턴스를 생성 + JwtVerificationFilter에서 사용되는 객체들을 생성자로 DI
            JwtVerificationFilter jwtVerificationFilter = new JwtVerificationFilter(jwtTokenizer, authorityUtils);

            // addFilter() 메서드를 통해 JwtAuthenticationFilter를 Spring Security Filter Chain에 추가
            builder.addFilter(jwtAuthenticationFilter)
                    // JwtVerificationFilter를 JwtAuthenticationFilter 뒤에 추가
                    // JwtAuthenticationFilter에서 로그인 인증에 성공한 후 발급받은 JWT가
                    // 클라이언트의 request header(Authorization 헤더)에 포함되어 있을 경우에만 동작
                    .addFilterAfter(jwtVerificationFilter, JwtAuthenticationFilter.class);
        }
    }
}
