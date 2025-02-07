package com.springboot.auth.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.springboot.auth.dto.LoginDto;
import com.springboot.auth.jwt.JwtTokenizer;
import com.springboot.member.entity.Member;
import lombok.SneakyThrows;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

// UsernamePasswordAuthenticationFilter는 폼 로그인 방식에서 사용하는 디폴트 Security Filter로
// 폼 로그인이 아니더라도 Username/Password 기반의 인증을 처리하기 위해 확장해서 구현할 수 있음
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;
    private final JwtTokenizer jwtTokenizer;

    // AuthenticationManager : 로그인 인증 정보를 전달받아 UserDetailsService와 인터랙션 한 뒤 인증 여부 판단.
    // JwtTokenizer : 클라이언트가 인증에 성공할 경우, JWT를 생성 및 발급하는 역할
    public JwtAuthenticationFilter(AuthenticationManager authenticationManager, JwtTokenizer jwtTokenizer) {
        this.authenticationManager = authenticationManager;
        this.jwtTokenizer = jwtTokenizer;
    }

    // 메서드 내부에서 인증을 시도하는 로직 구현
    // ObjectMapper : 인증정보를 DTO 클래스로 역직렬화 하기위함.
    @SneakyThrows
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response){
        ObjectMapper objectMapper = new ObjectMapper();

        // ServletInputStream 을 LoginDto 클래스의 객체로 역직렬화
        LoginDto loginDto = objectMapper.readValue(request.getInputStream(), LoginDto.class);
        //  Username과 Password 정보를 포함한 UsernamePasswordAuthenticationToken 생성
        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(loginDto.getUsername(), loginDto.getPassword());

        // UsernamePasswordAuthenticationToken -> AuthenticationManager 로 전달하면서 인증 처리를 위임
        return authenticationManager.authenticate(authenticationToken);
    }

    // 클라이언트의 인증 정보를 이용해 인증에 성공할 경우 호출
    @Override
    protected void successfulAuthentication(HttpServletRequest request,
                                            HttpServletResponse response,
                                            FilterChain chain,
                                            Authentication authResult) throws ServletException, IOException {
        // authResult.getPrincipal()로 Member 엔티티 클래스의 객체 할당
        // AuthenticationManager 내부에서 인증에 성공하면
        // 인증된 Authentication 객체가 생성되면서 principal 필드에 Member 객체가 할당
        Member member = (Member) authResult.getPrincipal();

        // Access Token 생성
        String accessToken = delegateAccessToken(member);
        // Refresh Token 생성
        String refreshToken = delegateRefreshToken(member);

        // response header(Authorization)에 Access Token 추가
        // 애플리케이션 측에 요청을 보낼 때마다 request header 에 추가해서 클라이언트 측의 자격을 증명하는 데 사용
        response.setHeader("Authorization", "Bearer " + accessToken);
        // response header(Refresh)에 Refresh Token 추가
        // refresh 토큰은 Access 토큰이 만료될 경우 새로 발급 받을 때 쓰이고,
        // access 토큰을 발급할 때 refresh 토큰도 같이 새로 발급 받으면 여러 문제 방지
        response.setHeader("Refresh", refreshToken);

        // onAuthenticationSuccess() 메서드를 호출하면
        // 구현한 MemberAuthenticationSuccessHandler onAuthenticationSuccess() 메서드가 알아서 호출
        // 별도의 코드를 추가하지 않아도 로그인 인증에 실패하면 onAuthenticationFailure() 자동 호출됨.
        this.getSuccessHandler().onAuthenticationSuccess(request, response, authResult);
    }

    // Chapter - JWT(JSON Web Token) 개요 > JWT 생성 및 검증 테스트
    private String delegateAccessToken(Member member){
        Map<String, Object> claims = new HashMap<>();
        claims.put("username", member.getEmail());
        claims.put("roles", member.getRoles());

        String subject = member.getEmail();
        Date expiration = jwtTokenizer.getTokenExpiration(jwtTokenizer.getAccessTokenExpirationMinutes());

        String base64EncodedSecretKey = jwtTokenizer.encodeBase64SecretKey(jwtTokenizer.getSecretKey());

        String accessToken = jwtTokenizer.generateAccessToken(claims, subject, expiration, base64EncodedSecretKey);

        return accessToken;
    }

    // Chapter - JWT(JSON Web Token) 개요 > JWT 생성 및 검증 테스트
    private String delegateRefreshToken(Member member){
        String subject = member.getEmail();
        Date expiration = jwtTokenizer.getTokenExpiration(jwtTokenizer.getRefreshTokenExpirationMinutes());
        String base64EncodedSecretKey = jwtTokenizer.encodeBase64SecretKey(jwtTokenizer.getSecretKey());

        String refreshToken = jwtTokenizer.generateRefreshToken(subject, expiration, base64EncodedSecretKey);

        return refreshToken;
    }
}
