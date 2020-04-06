package com.fateasstring.securitydemo.service;

import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;

@Service
public class MethodService {

    /** 只有admin的角色才能访问 */
    @PreAuthorize("hasRole('admin')")
    public String admin(){
        return "hello admin!!";
    }

    @Secured("ROLE_user")
    public String user(){
        return "hello user!";
    }

    @PreAuthorize("hasAnyRole('admin','user')")
    public String hello(){
        return "hello hello!!";
    }
}
