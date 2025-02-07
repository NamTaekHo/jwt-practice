package com.springboot.auth.handler;

import com.google.gson.Gson;
import com.springboot.response.ErrorResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

// 로그인 인증 실패 시 추가 작업 가능
// AuthenticationFailureHandler 인터페이스에는 onAuthenticationFailure() 추상 메서드가 정의되어 있어,
// onAuthenticationFailure() 메서드를 구현해서 추가 처리
@Slf4j
public class MemberAuthenticationFailureHandler implements AuthenticationFailureHandler {
    @Override
    public void onAuthenticationFailure(HttpServletRequest request,
                                        HttpServletResponse response,
                                        AuthenticationException exception) throws IOException {
        // 인증 실패 시, 에러 로그를 기록하거나 error response를 전송 할 수 있음
        log.error("# Authentication failed: {}", exception.getMessage());

        // sendErrorResponse() 메서드를 호출해 출력 스트림에 Error 정보 담음.
        sendErrorResponse(response);
    }

    private void sendErrorResponse(HttpServletResponse response) throws IOException {
        // JSON 문자열로 변환하기 위해 Gson 객체 생성
        Gson gson = new Gson();
        //  ErrorResponse 객체를 생성, ErrorResponse.of() 메서드로 HttpStatus.UNAUTHORIZED 상태 코드를 전달
        ErrorResponse errorResponse = ErrorResponse.of(HttpStatus.UNAUTHORIZED);
        // response의 Content Type이 json 이라는 것을 클라이언트에게 알려줄 수 있도록 HTTP Header에 추가
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        // response의 status가 401임을 알려줌.
        response.setStatus(HttpStatus.UNAUTHORIZED.value());
        // Gson으로 ErrorResponse 를 JSON 포맷 문자열로 변환 후 출력 스트림 생성
        response.getWriter().write(gson.toJson(errorResponse, ErrorResponse.class));
    }
}
