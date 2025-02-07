package com.springboot.auth.filter;

import com.springboot.auth.jwt.JwtTokenizer;
import com.springboot.auth.utils.AuthorityUtils;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.security.SignatureException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import java.util.Map;

// 클라이언트 측에서 전송된 request header에 포함된 JWT에 대해 검증 작업을 수행
// Spring Security 에서는 OncePerRequestFilter를 확장해서 request 당 한 번만 실행되는 Security Filter를 구현할 수 있다.
// JWT의 검증은 request 당 단 한 번만 수행하면 되기 때문에 JWT 전용 Filter로 만들기에는 OncePerRequestFilter 를 이용하는 것이 적절.
// JWT 검증을 request 당 단 한 번만 수행하는 이유는
//  -> JWT 검증은 성공 또는 실패라는 단일 결과를 도출하는 작업이고
//  -> 인증 필터는 사용자의 요청이 유효한지 판단하기 위해 토큰을 확인하고, 결과에 따라 요청을 처리하거나 차단하기에 한 번의 검증으로 충분.
public class JwtVerificationFilter extends OncePerRequestFilter {
    private final JwtTokenizer jwtTokenizer;
    private final AuthorityUtils authorityUtils;

    // JwtTokenizer : JWT를 검증하고 Claims(토큰에 포함된 정보)를 얻는 데 사용.
    // CustomAuthorityUtils : 검증에 성공하면 Authentication 객체에 채울 사용자의 권한을 생성하는 데 사용
    public JwtVerificationFilter(JwtTokenizer jwtTokenizer, AuthorityUtils authorityUtils) {
        this.jwtTokenizer = jwtTokenizer;
        this.authorityUtils = authorityUtils;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        // try~catch문으로 특정 예외가 발새하면 해당 Exception을 처리
        // 일반적인 예외처리는 Exception 을 catch 하면 throw로 예외를 던지거나 했는데 request.setAttribute()만 설정함
        // -> 예외가 발생하게 되면 SecurityContext 에 클라이언트의 인증 정보가 저장되지 않음.
        // SecurityContext에 클라이언트의 인증 정보가 저장되지 않고 다음 filter 로직을 수행하면
        // 결국 내부에서 AuthenticationException이 발생하고 이는 AuthenticationEntryPoint 가 처리한다.
        try {
            //  JWT를 검증하는 데 사용되는 private 메서드
            Map<String, Object> claims = verifyJws(request);
            //  Authentication 객체를 SecurityContext에 저장하기 위한 private 메서드
            setAuthenticationToContext(claims);
        } catch (SignatureException se) {
            request.setAttribute("exception", se);
        } catch (ExpiredJwtException ee) {
            request.setAttribute("exception", ee);
        } catch (Exception e) {
            request.setAttribute("exception", e);
        }

        // JWT의 서명 검증에 성공하고, Security Context에 Authentication 저장한 뒤
        // 다음(Next) Security Filter 호출
        filterChain.doFilter(request, response);
    }

    //  OncePerRequestFilter의 shouldNotFilter()를 오버라이드
    // 특정 조건에 부합하면(true이면) 해당 Filter의 동작을 수행하지 않고 다음 Filter로 건너뜀.
    // -> JWT 자격 증명이 필요한 리소스 요청인데 실수로 JWT를 포함하지 않았다 하더라도
    // Authentication이 정상적으로 SecurityContext에 저장되지 않은 상태이기 때문에
    // 다른 Security Filter를 거쳐 결국 Exception 던짐.
    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
        //  Authorization header의 값을 얻음.
        String authorization = request.getHeader("Authorization");
        // Authorization header의 값이 null이거나 Authorization header의 값이 “Bearer”로 시작하지 않는다면
        // 해당 Filter의 동작을 수행하지 않음
        return authorization == null || !authorization.startsWith("Bearer");
    }

    // JWT 검증
    private Map<String, Object> verifyJws(HttpServletRequest request) {
        //  request의 header에서 JWT를 얻음.
        // ->  클라이언트의 로그인 인증이 성공적으로 수행되면, 서버 측에서 Authorization header에 JWT를 추가하고
        // -->  여기는 클라이언트가 response header 로 전달받은 JWT를 request header에 추가해서 서버 측에 전송함.
        // 변수명 jws -> 서명된 JWT를 JWS(JSON Web Token Signed)라고 부르기 때문
        String jws = request.getHeader("Authorization").replace("Bearer ", "");
        //  JWT 서명(Signature)을 검증하기 위한 Secret Key
        String base64EncodedSecretKey = jwtTokenizer.encodeBase64SecretKey(jwtTokenizer.getSecretKey());
        // JWT에서 Claims 파싱 -> 내부적으로 서명(Signature) 검증에 성공했다는 의미
        // Claims가 정상적으로 파싱이 되면 서명 검증 역시 자연스럽게 성공한거임.
        Map<String, Object> claims = jwtTokenizer.getClaims(jws, base64EncodedSecretKey).getBody();

        return claims;
    }

    // Authentication 객체를 SecurityContext에 저장하기 위한 메서드
    private void setAuthenticationToContext(Map<String, Object> claims) {
        //  JWT에서 파싱 한 Claims에서 username 얻음.
        String username = (String) claims.get("username");
        // Claims에서 얻은 권한 정보를 기반으로 List<GrantedAuthority를 생성
        List<GrantedAuthority> authorities = authorityUtils.createAuthorities((List) claims.get("roles"));
        // username과 List<GrantedAuthority를 포함한 Authentication 객체를 생성
        Authentication authentication = new UsernamePasswordAuthenticationToken(username, null, authorities);
        // SecurityContext에 Authentication 객체를 저장
        SecurityContextHolder.getContext().setAuthentication(authentication);
    }

}
