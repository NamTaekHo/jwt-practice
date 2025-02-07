package com.springboot.auth.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.io.Encoders;
import io.jsonwebtoken.security.Keys;
import lombok.Getter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Calendar;
import java.util.Date;
import java.util.Map;

@Component
public class JwtTokenizer {
    @Getter
    @Value("${jwt.key}")
    private String secretKey;

    @Getter
    @Value("${jwt.access-token-expiration-minutes}")
    private int accessTokenExpirationMinutes;

    @Getter
    @Value("${jwt.refresh-token-expiration-minutes}")
    private int refreshTokenExpirationMinutes;

    // Plain text 형태의 Secret Key의 byte[]를 Base64 형식의 문자열로 인코딩해줌.
    public String encodeBase64SecretKey(String secretKey){
        return Encoders.BASE64.encode(secretKey.getBytes(StandardCharsets.UTF_8));
    }

    // 인증된 사용자에게 JWT를 최초로 발급해 주기 위한 JWT 생성 메서드
    public String generateAccessToken(Map<String, Object> claims,
                                      String subject,
                                      Date expiration,
                                      String base64EncodedSecretKey){
        // Base64 형식 Secret Key 문자열을 이용해 Key 객체 가져옴
        Key key = getKeyFromBase64EncodedKey(base64EncodedSecretKey);

        return Jwts.builder()
                // JWT에 포함시킬 Custom Claims 추가
                // 주로 인증된 사용자와 관련된 정보를 추가
                .setClaims(claims)
                // JWT에 대한 제목 추가
                .setSubject(subject)
                // JWT 발행 일자를 설정하는데 파라미터 타입은 Date타입
                .setIssuedAt(Calendar.getInstance().getTime())
                // JWT의 만료일시 지정, Date타입
                .setExpiration(expiration)
                // 서명을 위한 Key 객체 설정
                .signWith(key)
                // JWT를 생성하고 직렬화
                .compact();
    }

    // Access Token이 만료되었을 경우, 새로 생성할 수 있게 해주는 Refresh Token 생성 메서드
    // Refresh 토큰의 경우 Access Token 을 새로 발급해 주는 역할이기 때문에 별도의 Custom Claims는 추가 필요 x
    public String generateRefreshToken(String subject, Date expiration, String base64EncodedSecretKey){
        Key key = getKeyFromBase64EncodedKey(base64EncodedSecretKey);

        return Jwts.builder()
                .setSubject(subject)
                .setIssuedAt(Calendar.getInstance().getTime())
                .setExpiration(expiration)
                .signWith(key)
                .compact();
    }

    // 전달받은 jws에서 claims 추출하는 메서드
    public Jws<Claims> getClaims(String jws, String base64EncodedSecretKey){
        // Base64로 인코딩된 Secret Key를 이용해 Key 객체생성
        Key key = getKeyFromBase64EncodedKey(base64EncodedSecretKey);

        // 전달받은 JWS를 파싱하여 Claims 객체 추출
        Jws<Claims> claims =
                // JWT 파서를 생성하는 메서드
                Jwts.parserBuilder()
                        // 서명을 검증하기 위해 사용할 Secret Key 설정
                .setSigningKey(key)
                        // JWT 파서 빌드
                .build()
                        // 전달받은 JWS를 파싱하고 서명을 검증하여 Claims 반환
                .parseClaimsJws(jws);
        return claims;
    }

    // JWT에 포함된 Signature를 검증해서 위/변조 확인 메서드
    // jws는 Signature가 포함된 JWT라는 의미
    // 검증하는 용도이므로 Claims 리턴 필요 x
    public void verifySignature(String jws, String base64EncodedSecretKey){
        Key key = getKeyFromBase64EncodedKey(base64EncodedSecretKey);
        Jwts.parserBuilder()
                // 서명에 사용된 Secret Key 설정
                .setSigningKey(key)
                .build()
                // JWT를 파싱해서 Claims 얻음.
                .parseClaimsJws(jws);
    }

    // Token의 만료일자를 가져오는 메서드
    public Date getTokenExpiration(int expirationMinutes){
        Calendar calendar = Calendar.getInstance();
        calendar.add(Calendar.MINUTE, expirationMinutes);
        Date expiration = calendar.getTime();

        return expiration;
    }

    // JWT의 서명에 사용할 Secret Key 생성
    private Key getKeyFromBase64EncodedKey(String base64EncodedSecretKey){
        // Base64 형식으로 인코딩 된 Secret Key를 디코딩 한 후, byte array 반환
        byte[] keyBytes = Decoders.BASE64.decode(base64EncodedSecretKey);
        // key byte array를 기반으로 적절한 HMAC 알고리즘을 적용한 Key 객체 생성
        Key key = Keys.hmacShaKeyFor(keyBytes);
        return key;
    }


}
