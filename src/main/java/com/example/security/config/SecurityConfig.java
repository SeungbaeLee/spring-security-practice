package com.example.security.config;

import com.example.security.oauth.PrincipalOauth2UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.WebSecurityConfigurer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;


// oauth-> 1.코드받기(인증) 2. 엑세스토큰(권한)
// 3.사용자프로필 정보를 가져와서 4-1. 그 정보를 토대로 회원가입을 자동으로 진행시키기도 함
// 4-2 추가정보가 필요하다면(이메일,전화번호,이름,아이디)쇼핑몰 -> (집주소), 백화점몰 -> (vip등급,일반등급) 추가 입력 후 회원가입 진행
@Configuration
@EnableWebSecurity // 스프링 시큐리티 필터가 스프링 필터체인에 등록이 됨
@EnableGlobalMethodSecurity(securedEnabled = true, prePostEnabled = true)//Secured 어노테이션 활성화,preAuthorize 어노테이션 활성화
public class SecurityConfig {

    @Autowired
    private PrincipalOauth2UserService principalOauth2UserService;

    @Bean  // @Bean의 역할은 해당 메서드의 return 되는 Object를 IoC로 등록해줌
    public BCryptPasswordEncoder encoderPwd() {
        return new BCryptPasswordEncoder();
    }


    @Bean
    SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .csrf(cs -> cs.disable())
                .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .formLogin(f -> f.disable())
                .httpBasic(h -> h.disable())
                .formLogin(f->f.loginPage("/loginForm").loginProcessingUrl("/login").defaultSuccessUrl("/"))
                .oauth2Login(o->o.loginPage("/loginForm").userInfoEndpoint(u->u.userService(principalOauth2UserService)))
                .authorizeHttpRequests(authorize -> {
                    authorize
                            .requestMatchers("/user/**").authenticated()//인증만 되면 들어갈 수 있는 주소
                            .requestMatchers("manager/**").hasAnyRole("hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
                            .requestMatchers("/admin/**").hasAnyRole("hasRole('ROLE_ADMIN')")
                            .anyRequest().permitAll();
                });
        return http.build();

    }
}
