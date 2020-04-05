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
