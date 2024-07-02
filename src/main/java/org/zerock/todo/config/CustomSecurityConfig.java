package org.zerock.todo.config;

import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.zerock.todo.security.APIUserDetailsService;
import org.zerock.todo.security.filter.APILoginFilter;
import org.zerock.todo.security.filter.RefreshTokenFilter;
import org.zerock.todo.security.filter.TokenCheckFilter;
import org.zerock.todo.security.handler.APILoginSuccessHandler;
import org.zerock.todo.util.JWTUtil;

import java.util.Arrays;
@Log4j2
@RequiredArgsConstructor
@EnableWebSecurity @EnableGlobalMethodSecurity(prePostEnabled = true)
@Configuration
public class CustomSecurityConfig {
    
    private final APIUserDetailsService apiUserDetailsService;
    private final JWTUtil jwtUtil;

    @Bean // 패스워드 암호화
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean // 정적 자원 요청에 대한 보안 무시
    public WebSecurityCustomizer webSecurityCustomizer() {
        log.info("----------config.CustomSecurityConfig.webSecurityCustomizer(정적 요청 관련)");
        return (web) -> web.ignoring()
                .requestMatchers(PathRequest
                                .toStaticResources()
                                .atCommonLocations()
                );
    }

    @Bean // http 보안 구성
    public SecurityFilterChain filterChain(
            final HttpSecurity http
    ) throws Exception {
        log.info("----------config.CustomSecurityConfig.filterChain(http 보안)");

        // AuthenticationManager 사용자 인증 설정
        AuthenticationManagerBuilder authenticationManagerBuilder = http.getSharedObject(AuthenticationManagerBuilder.class);
        authenticationManagerBuilder.userDetailsService(apiUserDetailsService).passwordEncoder(passwordEncoder());

        // AuthenticationManager 생성
        AuthenticationManager authenticationManager = authenticationManagerBuilder.build();

        // http 보안 구성에 AuthenticationManager 등록
        http.authenticationManager(authenticationManager);

        // APILoginFilter 설정
        APILoginFilter apiLoginFilter = new APILoginFilter("/generateToken");
        apiLoginFilter.setAuthenticationManager(authenticationManager);

        // APILoginSuccessHandler 설정
        APILoginSuccessHandler successHandler = new APILoginSuccessHandler(jwtUtil);
        apiLoginFilter.setAuthenticationSuccessHandler(successHandler);

        // http 요청 -> 전처리 작업
        //// security 필터에 커스텀 필터 추가, token 생성
        http.addFilterBefore(apiLoginFilter, UsernamePasswordAuthenticationFilter.class);
        //// api로 시작하는 모든 경로는 TokenCheckFilter 동작
        http.addFilterBefore(
                tokenCheckFilter(jwtUtil, apiUserDetailsService),
                UsernamePasswordAuthenticationFilter.class
        );
        //// refreshToken 호출 처리
        http.addFilterBefore(
                new RefreshTokenFilter("/refreshToken", jwtUtil),
                TokenCheckFilter.class
        );

        http.csrf().disable(); // csrf 방지 (csrf 토큰 미포함)
        // 세션 관리, 모든 세션 비활성화
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
        // cors 설정
        http.cors(httpSecurityCorsConfigurer -> {
            httpSecurityCorsConfigurer.configurationSource(corsConfigurationSource());
        });

        return http.build();
    }
    @Bean // CORS 설정
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOriginPatterns(Arrays.asList("*"));
        configuration.setAllowedMethods(Arrays.asList("HEAD", "GET", "POST", "PUT", "DELETE"));
        configuration.setAllowedHeaders(Arrays.asList("Authorization", "Cache-Control", "Content-Type"));
        configuration.setAllowCredentials(true);
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }
    private TokenCheckFilter tokenCheckFilter(
            JWTUtil jwtUtil,
            APIUserDetailsService apiUserDetailsService
    ){
        return new TokenCheckFilter(apiUserDetailsService, jwtUtil);
    }
}
