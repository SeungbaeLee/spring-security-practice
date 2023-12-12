package com.example.security.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.WebSecurityConfigurer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity // 스프링 시큐리티 필터가 스프링 필터체인에 등록이 됨
@EnableGlobalMethodSecurity(securedEnabled = true, prePostEnabled = true)//Secured 어노테이션 활성화,preAuthorize 어노테이션 활성화
public class SecurityConfig {

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
//                .oauth2Login(o->o.loginPage("/loginForm"))//구글 로그인이 완료된 뒤의 후처리가 필요
                .authorizeHttpRequests(authorize -> {
                    authorize
                            .requestMatchers("/user/**").authenticated()//인증만 되면 들어갈 수 있는 주소
                            .requestMatchers("manager/**").hasAnyRole("hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
                            .requestMatchers("/admin/**").hasAnyRole("hasRole('ROLE_ADMIN')")
                            .anyRequest().permitAll();
                });

//        http.formLogin(f->f.loginProcessingUrl("/loginForm"));
        return http.build();

    }
}
