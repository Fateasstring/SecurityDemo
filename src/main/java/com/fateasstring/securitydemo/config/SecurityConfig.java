package com.fateasstring.securitydemo.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.*;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.HashMap;
import java.util.Map;

//@Configuration              /** 继承 */
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
                .withUser("wu").password("123").roles("user");
    }

    /** HttpSecurity配置 */
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()                 /** hasRole具备角色 */
                .antMatchers("/admin/**").hasRole("admin")
                .antMatchers("/user/**").hasAnyRole("admin","user")  /** 具备其中一个Role */
                .anyRequest().authenticated()
                .and()
                .formLogin()  /** 表单登陆 */
                .loginProcessingUrl("/doLogin")
                .loginPage("/login")  /** 跳转到默认的或者自定义登陆页面 */
                .usernameParameter("username")
                .passwordParameter("password")

                /** 登陆成功设置 */
                .successHandler(new AuthenticationSuccessHandler() {
                    @Override
                    public void onAuthenticationSuccess(HttpServletRequest req, HttpServletResponse resp, Authentication authentication) throws IOException, ServletException {
                        /** authentication保存刚刚登陆的用户信息 */

                        /** 给前端返回Json格式数据 */
                        resp.setContentType("application/json;charset=utf-8");
                        PrintWriter out = resp.getWriter();
                        Map<String, Object> map = new HashMap<>();
                        map.put("status",200);

                        /** 获取登陆成功的用户对象 */
                        map.put("msg",authentication.getPrincipal());
                        out.write(new ObjectMapper().writeValueAsString(map));
                        out.flush();
                        out.close();
                    }
                })

                /** 登陆失败设置 */
                .failureHandler(new AuthenticationFailureHandler() {
                    @Override
                    public void onAuthenticationFailure(HttpServletRequest req, HttpServletResponse resp, AuthenticationException e) throws IOException, ServletException {
                        /** 给前端返回Json格式数据 */
                        resp.setContentType("application/json;charset=utf-8");
                        PrintWriter out = resp.getWriter();
                        Map<String, Object> map = new HashMap<>();
                        map.put("status",401);
                        if (e instanceof LockedException){
                            map.put("msg","账户被锁定，登陆失败！");
                        }else if (e instanceof BadCredentialsException){
                            map.put("msg","用户名或密码输入错误！");
                        }else if (e instanceof DisabledException){
                            map.put("msg","账户被禁用，登陆失败！");
                        }else if (e instanceof AccountExpiredException){
                            map.put("msg","账户过期，登陆失败！");
                        }else if (e instanceof CredentialsExpiredException){
                            map.put("msg","密码过期，登陆失败！");
                        }else {
                            map.put("msg","未知错误，登陆失败！");
                        }
                        out.write(new ObjectMapper().writeValueAsString(map));
                        out.flush();
                        out.close();
                    }
                })
                .and()
                .logout()
                .logoutUrl("/logout")
                /** 注销成功回调函数 */
                .logoutSuccessHandler(new LogoutSuccessHandler() {
                    @Override
                    public void onLogoutSuccess(HttpServletRequest req, HttpServletResponse resp, Authentication authentication) throws IOException, ServletException {
                        /** 给前端返回Json格式数据 */
                        resp.setContentType("application/json;charset=utf-8");
                        PrintWriter out = resp.getWriter();
                        Map<String, Object> map = new HashMap<>();
                        map.put("status",200);
                        map.put("msg","注销登陆成功！");
                        out.write(new ObjectMapper().writeValueAsString(map));
                        out.flush();
                        out.close();
                    }
                })
                .permitAll() /** 给没有登陆的用户直接过 */
                .and()
                .csrf().disable(); /** 关闭csr攻击保护，方便使用postman测试 */
    }
}

