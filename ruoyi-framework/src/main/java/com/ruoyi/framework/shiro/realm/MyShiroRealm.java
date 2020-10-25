package com.ruoyi.framework.shiro.realm;

import com.ruoyi.framework.config.ShiroConfig;
import com.ruoyi.system.domain.SysUser;
import com.ruoyi.system.service.ISysMenuService;
import com.ruoyi.system.service.ISysRoleService;
import com.ruoyi.system.service.ISysUserService;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.*;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.cas.CasRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;

import javax.annotation.PostConstruct;
import java.util.HashSet;
import java.util.Set;

public class MyShiroRealm extends CasRealm {

    private static final Logger log = LoggerFactory.getLogger(MyShiroRealm.class);

    @Autowired
    private ISysMenuService menuService;

    @Autowired
    private ISysRoleService roleService;

    @Autowired
    private ISysUserService userService;


    @PostConstruct
    public void initProperty() {
        setCasServerUrlPrefix(ShiroConfig.casServerUrlPrefix);
        // 客户端回调地址
        setCasService(ShiroConfig.shiroServerUrlPrefix + ShiroConfig.casFilterUrlPattern);
    }

    /**
     * 此方法调用 hasRole,hasPermission的时候才会进行回调.
     * <p>
     * 权限信息.(授权): 1、如果用户正常退出，缓存自动清空； 2、如果用户非正常退出，缓存自动清空；
     * 3、如果我们修改了用户的权限，而用户不退出系统，修改的权限无法立即生效。 （需要手动编程进行实现；放在service进行调用）
     * 在权限修改后调用realm中的方法，realm已经由spring管理，所以从spring中获取realm实例， 调用clearCached方法；
     * :Authorization 是授权访问控制，用于对用户进行的操作授权，证明该用户是否允许进行当前操作，如访问某个链接，某个资源文件等。
     *
     * @param principals
     * @return
     */
    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {

        String username = (String) SecurityUtils.getSubject().getSession().getAttribute("username");
        // 查询用户信息
        SysUser user = userService.selectUserByLoginName(username);

        // 角色列表
        Set<String> roles = new HashSet<String>();
        // 功能列表
        Set<String> menus = new HashSet<String>();
        SimpleAuthorizationInfo info = new SimpleAuthorizationInfo();
        // 管理员拥有所有权限
        if (user.isAdmin()) {
            info.addRole("admin");
            info.addStringPermission("*:*:*");
        } else {
            roles = roleService.selectRoleKeys(user.getUserId());
            menus = menuService.selectPermsByUserId(user.getUserId());
            // 角色加入AuthorizationInfo认证对象
            info.setRoles(roles);
            // 权限加入AuthorizationInfo认证对象
            info.setStringPermissions(menus);
        }
        return info;

    }


    /**
     * 1、CAS认证 ,验证用户身份
     * 2、将用户基本信息设置到会话中,方便获取
     * 3、该方法可以直接使用CasRealm中的认证方法，此处仅用作测试
     */
    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) {
        // 调用父类中的认证方法，CasRealm已经为我们实现了单点认证。
        AuthenticationInfo authc = super.doGetAuthenticationInfo(token);
        if (authc == null) {
            System.out.println(" token is null");
        }

        // 获取登录的账号，cas认证成功后，会将账号存起来
        if (authc != null && authc.getPrincipals() != null) {
            String account = (String) authc.getPrincipals().getPrimaryPrincipal();
            System.out.println("============123==========:" + account);
            // 将用户信息存入session中,方便程序获取,此处可以将根据登录账号查询出的用户信息放到session中
            SecurityUtils.getSubject().getSession().setAttribute("username", account);
        }

        return authc;
    }


    /**
     * 清理缓存权限
     */
    public void clearCachedAuthorizationInfo() {
        this.clearCachedAuthorizationInfo(SecurityUtils.getSubject().getPrincipals());
    }


}
