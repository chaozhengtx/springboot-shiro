package com.southwind.config;

import at.pollux.thymeleaf.shiro.dialect.ShiroDialect;
import com.southwind.realm.AccoutRealm;
import org.apache.shiro.spring.web.ShiroFilterFactoryBean;
import org.apache.shiro.web.mgt.DefaultWebSecurityManager;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.Hashtable;
import java.util.Map;

@Configuration
public class ShiroConfig {

    @Bean
    public ShiroFilterFactoryBean shiroFilterFactoryBean(@Qualifier("securityManager") DefaultWebSecurityManager securityManager){
        ShiroFilterFactoryBean shiroFilterFactoryBean = new ShiroFilterFactoryBean();
        shiroFilterFactoryBean.setSecurityManager(securityManager);
        //权限设置
        Map<String,String> map = new Hashtable<>();
        map.put("/main","authc");
        map.put("/manage","perms[cheak]");
        map.put("/administrator","roles[manager]");
        shiroFilterFactoryBean.setFilterChainDefinitionMap(map);
        //设置登录页面
        shiroFilterFactoryBean.setLoginUrl("/login");
        //设置未授权页面
        shiroFilterFactoryBean.setUnauthorizedUrl("/unauth");
        return shiroFilterFactoryBean;
    }


    @Bean
    public DefaultWebSecurityManager securityManager(@Qualifier("accoutRealm") AccoutRealm accoutRealm){
        DefaultWebSecurityManager manager = new DefaultWebSecurityManager();
        manager.setRealm(accoutRealm);
        return manager;
    }

    @Bean
    public AccoutRealm accoutRealm(){
        return new AccoutRealm();
    }

    @Bean
    public ShiroDialect shiroDialect(){
        return new ShiroDialect();
    }
}
