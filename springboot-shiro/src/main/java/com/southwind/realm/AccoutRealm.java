package com.southwind.realm;

import com.southwind.entity.Account;
import com.southwind.service.AccountService;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.*;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.util.ByteSource;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.HashSet;
import java.util.Set;

public class AccoutRealm extends AuthorizingRealm {

    @Autowired
    private AccountService accountService;

    /**
     * 授权
     * @param principalCollection
     * @return
     */
    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principalCollection) {
        //获取当前登录的用户信息
        Subject subject = SecurityUtils.getSubject();
        Account account = (Account) subject.getPrincipal();

        //设置角色
        Set<String> roles = new HashSet<>();
        roles.add(account.getRole());
        SimpleAuthorizationInfo info = new SimpleAuthorizationInfo(roles);

        //设置权限
        info.addStringPermission(account.getPerms());
        return info;
    }


    /**
     * 认证
     * @param authenticationToken
     * @return
     * @throws AuthenticationException
     */
    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken authenticationToken) throws AuthenticationException {
        //1. 把 AuthenticationToken 转换为 UsernamePasswordToken
        UsernamePasswordToken token = (UsernamePasswordToken) authenticationToken;

        //2. 调用数据库的方法, 从数据库中查询 username 对应的用户记录
        Account account = accountService.findByUsername(token.getUsername());

        //3. 根据用户的情况, 来构建 AuthenticationInfo 对象并返回.
        if(account != null){
            //通常使用的实现类为: SimpleAuthenticationInfo
            //1). principal: 认证的实体信息. 可以是 username, 也可以是数据表对应的用户的实体类对象.
            Object principal = account;
            //2). credentials: 密码.
            Object credentials = account.getPassword();
            //3). realmName: 当前 realm 对象的 name. 调用父类的 getName() 方法即可
            String realmName = getName();
            //4). 盐值. 需要唯一: 一般使用随机字符串或 user id
            //ByteSource credentialsSalt = ByteSource.Util.bytes(account.getUsername());

            SimpleAuthenticationInfo info = null;
//            info = new SimpleAuthenticationInfo(principal, credentials, credentialsSalt, realmName);
            info = new SimpleAuthenticationInfo(principal, credentials,  realmName);
            return info;
        }

        //4. 若用户不存在, 则可以抛出 UnknownAccountException 异常
        return null;
    }
}
