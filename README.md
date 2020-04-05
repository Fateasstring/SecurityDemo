# SecurityDemo
SpringBoot集成Security脚手架

# 1.创建项目

![image-20200404200707176](C:\Users\dell\AppData\Roaming\Typora\typora-user-images\image-20200404200707176.png)

![image-20200404200649364](C:\Users\dell\AppData\Roaming\Typora\typora-user-images\image-20200404200649364.png)



添加测试接口HelloController.class

![image-20200404200854481](C:\Users\dell\AppData\Roaming\Typora\typora-user-images\image-20200404200854481.png)



启动项目访问：http://localhost:8080/hello，

直接跳转：http://localhost:8080/login，默认用户为user。

![image-20200404201012925](C:\Users\dell\AppData\Roaming\Typora\typora-user-images\image-20200404201012925.png)

密码：

![image-20200404201134821](C:\Users\dell\AppData\Roaming\Typora\typora-user-images\image-20200404201134821.png)

登陆成功：

![image-20200404201210222](C:\Users\dell\AppData\Roaming\Typora\typora-user-images\image-20200404201210222.png)

# 2.手工配置用户名密码

## 2.1 application.properties配置

在src/main/resources/application.properties中添加代码：

```java
spring.security.user.password=123
spring.security.user.name=fate
spring.security.user.roles=admin
```

访问http://localhost:8080/hello，登陆后可显示 Hello security!

## 2.2 代码配置

分别新增config和controller两个文件夹

![image-20200404205909071](C:\Users\dell\AppData\Roaming\Typora\typora-user-images\image-20200404205909071.png)

创建SecurityConfig.class

```java
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


```

访问http://localhost:8080/hello，登陆后可显示 Hello security!

# 3.HttpSecurity配置

SecurityConfig.class中新增代码：

```java
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
                .permitAll() /** 给没有登陆的用户直接过 */
                .and()
                .csrf().disable(); /** 关闭csr攻击保护，方便使用postman测试 */
    }
}
```

HelloController.class中新增接口：

```java
@RestController
public class HelloController {

    @GetMapping("/hello")
    public String hello(){
        return "Hello security!";
    }

    @GetMapping("/admin/hello")
    public String admin(){
        return "Hello admin!!";
    }

    @GetMapping("/user/hello")
    public String user(){
        return "hello user!";
    }
}

```

使用fate登陆后：

访问http://localhost:8080/hello，得到： Hello security!

访问http://localhost:8080/admin/hello，得到：Hello admin!!

访问http://localhost:8080/user/hello，得到：hello user!

使用wu登陆后：

访问http://localhost:8080/hello，得到： Hello security!

访问http://localhost:8080/admin/hello，报错:

```java
Whitelabel Error Page

This application has no explicit mapping for /error, so you are seeing this as a fallback.
Sat Apr 04 23:35:06 CST 2020
There was an unexpected error (type=Forbidden, status=403).
Forbidden
```

访问http://localhost:8080/user/hello，

访问http://localhost:8080/user/hello，得到：hello user!

# 4.登陆表单详细配置

HelloController.class新增login()函数：

```java
package com.fateasstring.securitydemo.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HelloController {

    @GetMapping("/hello")
    public String hello(){
        return "Hello security!";
    }

    @GetMapping("/admin/hello")
    public String admin(){
        return "Hello admin!!";
    }

    @GetMapping("/user/hello")
    public String user(){
        return "hello user!";
    }

    @GetMapping("/login")
    public String login(){
        return "please login!!";
    }
}

```

修改SecurityConfig.class，新增函数如下：

```
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
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.HashMap;
import java.util.Map;

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
                .permitAll() /** 给没有登陆的用户直接过 */
                .and()
                .csrf().disable(); /** 关闭csr攻击保护，方便使用postman测试 */
    }
}


```

使用postman测试：

http://localhost:8080/doLogin?username=fate&password=123

返回结果：

```java
{
    "msg": {
        "password": null,
        "username": "fate",
        "authorities": [
            {
                "authority": "ROLE_admin"
            }
        ],
        "accountNonExpired": true,
        "accountNonLocked": true,
        "credentialsNonExpired": true,
        "enabled": true
    },
    "status": 200
}
```

![image-20200405203714382](C:\Users\dell\AppData\Roaming\Typora\typora-user-images\image-20200405203714382.png)

# 5.注销登陆配置

修改SecurityConfig.class，如下：

```java
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


```

post请求访问：http://localhost:8080/doLogin?username=fate&password=123

登陆成功后，get方式访问：http://localhost:8080/logout

返回：

```java
{
    "msg": "注销登陆成功！",
    "status": 200
}
```

# 6.多个HttpSecurity配置

注释SecurityConfig.class中的@Configuration ，如图：

![image-20200405205401747](C:\Users\dell\AppData\Roaming\Typora\typora-user-images\image-20200405205401747.png)

在config中新建MultiHttpSecurityConfig.class,

```java
package com.fateasstring.securitydemo.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
public class MultiHttpSecurityConfig {

    @Bean
    PasswordEncoder passwordEncoder(){
        return NoOpPasswordEncoder.getInstance();
    }

    @Autowired
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        /** 配置用户名密码 */
        auth.inMemoryAuthentication()
                .withUser("fate").password("123").roles("admin")
                .and()
                .withUser("wu").password("123").roles("user");
    }

    @Configuration
    @Order(1) /** @Order 用于优先级问题，数字越小，优先级越大 */
    /** 内部静态类 */
    public static class AdminSecurityConfig extends WebSecurityConfigurerAdapter{
        @Override
        protected void configure(HttpSecurity http) throws Exception {
            /** /admin/** 格式的路径统统只有admin角色的权限才能访问  */
            http.antMatcher("/admin/**").authorizeRequests().anyRequest().hasAnyRole("admin");
        }
    }

    @Configuration
    public static class OtherSercurityConfig extends WebSecurityConfigurerAdapter{

        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http.authorizeRequests().anyRequest().authenticated()
                    .and()
                    .formLogin()
                    .loginProcessingUrl("/doLogin")
                    .permitAll()
                    .and()
                    .csrf().disable();
        }
    }

}

```

post方式访问：http://localhost:8080/doLogin?username=fate&password=123

结果：

```java
{
    "timestamp": "2020-04-05T13:19:20.218+0000",
    "status": 404,
    "error": "Not Found",
    "message": "No message available",
    "path": "/"
}
```

证明已经成功登陆，并跳转“/”页面，只是没有找到所以报错。

get方式访问：http://localhost:8080/admin/hello

返回：Hello admin!!

使用wu登陆：

http://localhost:8080/doLogin?username=wu&password=123

访问http://localhost:8080/admin/hello

则报错：

```java
{
    "timestamp": "2020-04-05T13:24:04.942+0000",
    "status": 403,
    "error": "Forbidden",
    "message": "Forbidden",
    "path": "/admin/hello"
}

```

访问http://localhost:8080/user/hello，则成功返回：hello user!

# 7.密码加密

在src/test/java/com/fateasstring/securitydemo/SecuritydemoApplicationTests.java

中添加代码：

```java
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@SpringBootTest
class SecuritydemoApplicationTests {

    @Test
    void contextLoads() {
        for (int i = 0; i < 10 ; i++){
            BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
            System.out.println(encoder.encode("123"));
        }
    }
}
```

输出结果：

```java
$2a$10$wdVd8kt7P2MAc8V9rTcEFenANInhlCe0qAd/gur9WVHFxox8w5PYC
$2a$10$HnwkiUg4SY12plOHoL1ACOikS0SnhjUHDuHbAvrVg3ZCK8R1oOap.
$2a$10$w1tHwMCTAjnNabUmI8kx7etY6cuC.Q.iul7TVPK/QK.bAd1nHmePW
$2a$10$mX5PYyqvGY./i6/kdcyMoOGQt172Kh93IRBhoWlGP8A7UFM1qv4s2
$2a$10$Pm5QWcq7f2GyotlwQD7Pb.TuxqQxaWsTPtGPhKL5pQepGlSzhYYOy
$2a$10$5MNTzAIlWx7BfmUZc.HvouO4tKIRDrwpWmEl3iKEKyVTHqVctr/Tu
$2a$10$9.X7sAlgn/VUOqMgZt6PwOuJFpjEfnq.illG3hwY/CJcEtDyiTZoa
$2a$10$1yZu.aGZ8wjMEViCiaOyvuNWgF4lEEFSxCTlUdq0d9q102ujOZZI2
$2a$10$imuCdqbb45pP179swv6Exe0Ed5s7cdAeXEtQyhIxlLwVD0YhRGYJC
$2a$10$Nld7e5PHHZciwcOmr3VKyeJq110ab61rAvMumatWFVTn0fsXwGf/y
```

Spring Security中使用**BCryptPasswordEncoder**方法对密码**进行加密**(encode)与**密码匹配**(matches)

BCryptPasswordEncoder方法采用SHA-256 +随机盐+密钥对密码进行加密。

1）加密(encode)：注册用户时，使用SHA-256+随机盐+密钥把用户输入的密码进行hash处理，得到密码的hash值，然后将其存入数据库中。

2）密码匹配(matches)：

​		在验证过程中，将用户输入的登录密码作为第一个参数，用从数据库取出的密文密码作为盐值，由此生成的密码，与数据库中存储的密码的生成策略相同。接着把二者（已加密的用户登录密码和数据库存储的密码）作为参数传递到黑色方框方法里得到验证结果。

参考链接：

https://blog.csdn.net/qq_41256709/article/details/90212393

https://www.cnblogs.com/chengxuxiaoyuan/p/11939084.html