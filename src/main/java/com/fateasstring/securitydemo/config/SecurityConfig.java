package com.fateasstring.securitydemo.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration              /** 继承 */
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    /**一个过期的方案，告诉系统密码不加密，
      后面再使用密码加密。
     * */
    @Bean
    PasswordEncoder passwordEncoder(){
        return NoOpPasswordEncoder.getInstance();
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        /** 配置用户名密码 */
        auth.inMemoryAuthentication()
                .withUser("fate").password("123").roles("admin")
                .and()
                .withUser("wu").password("123").roles("admin");
    }
}

