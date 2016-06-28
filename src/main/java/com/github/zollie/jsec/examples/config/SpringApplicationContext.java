package com.github.zollie.jsec.examples.config;

import com.github.zollie.jsec.web.ErrorSendingAccessDeniedHandler;
import com.github.zollie.jsec.krb5.AbstractJaasKerberosLoginConfiguration;
import com.github.zollie.jsec.krb5.GssKerberosServicePrincipal;
import com.github.zollie.jsec.krb5.IbmJaasKerberosClientLoginConfiguration;
import com.github.zollie.jsec.krb5.KerberosServicePrincipal;
import com.github.zollie.jsec.krb5.KerberosServicePrincipalTicketValidator;
import com.github.zollie.jsec.ldap.BaseLdapPathPoolingContextSourceAdapter;
import com.github.zollie.jsec.ldap.CachingFilterBasedLdapUserSearch;
import com.github.zollie.jsec.ldap.LdapAuthenticationUserDetailsService;
import com.github.zollie.jsec.x509.WebsphereX509AuthenticationFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.ldap.core.support.BaseLdapPathContextSource;
import org.springframework.ldap.pool.validation.DefaultDirContextValidator;
import org.springframework.ldap.pool.validation.DirContextValidator;
import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.access.expression.SecurityExpressionHandler;
import org.springframework.security.access.vote.AffirmativeBased;
import org.springframework.security.access.vote.RoleVoter;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.extensions.kerberos.KerberosServiceAuthenticationProvider;
import org.springframework.security.extensions.kerberos.web.SpnegoAuthenticationProcessingFilter;
import org.springframework.security.extensions.kerberos.web.SpnegoEntryPoint;
import org.springframework.security.ldap.DefaultSpringSecurityContextSource;
import org.springframework.security.ldap.search.LdapUserSearch;
import org.springframework.security.ldap.userdetails.DefaultLdapAuthoritiesPopulator;
import org.springframework.security.ldap.userdetails.LdapAuthoritiesPopulator;
import org.springframework.security.ldap.userdetails.LdapUserDetailsService;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.ExceptionTranslationFilter;
import org.springframework.security.web.access.expression.DefaultWebSecurityExpressionHandler;
import org.springframework.security.web.access.expression.ExpressionBasedFilterInvocationSecurityMetadataSource;
import org.springframework.security.web.access.expression.WebExpressionVoter;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;
import org.springframework.security.web.authentication.AnonymousAuthenticationFilter;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationProvider;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import java.util.Arrays;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;

/**
 * An example Spring Application Context
 *
 * <p>
 *     This config will setup a Spring Security filter that will use a client side X.509 cert if
 *     present. If no X.509 cert is found, it will then look for a SPNEGO token in an HTTP header.
 *     If a SPNEGO token is not found, a challenge will be returned to the browser per RFC 4559.
 *     If able, the browser would then get a TGS from the KDC, wrap it a SPNEGO token and resubmit
 *     the request with this token in the "WWW-Authenticate:" HTTP header.
 * </p>
 *
 * @author zollie
 */
@Configuration
public class SpringApplicationContext {
//    @Resource(mappedName="path/to/jndi")
//    @Inject
    private AppConfig config;

    @Bean
    public FilterChainProxy springSecurityFilterChain() throws Exception {
        // SecurityFilterChain
        SecurityFilterChain chain = new DefaultSecurityFilterChain(new AntPathRequestMatcher("/**"),
                // Filters ...
                preAuthAuthenticationFilter(),
                spnegoAuthenticationProcessingFilter(),
                anonymousAuthenticationFilter(),
                exceptionTranslationFilter(),
                filterSecurityInterceptor());
        return new FilterChainProxy(chain);
    }

    @Bean
    public FilterSecurityInterceptor filterSecurityInterceptor() {
        FilterSecurityInterceptor filterSecurityInterceptor = new FilterSecurityInterceptor();
        filterSecurityInterceptor.setAuthenticationManager(authenticationManager());
        filterSecurityInterceptor.setAccessDecisionManager(accessDecisionManager());

        ExpressionBasedFilterInvocationSecurityMetadataSource ms = new ExpressionBasedFilterInvocationSecurityMetadataSource(secPatternMap(), securityExpressionHandler());
        filterSecurityInterceptor.setSecurityMetadataSource(ms);
        try {
            filterSecurityInterceptor.afterPropertiesSet();
        } catch (Exception e) {
            throw new SecurityException(e);
        }
        return filterSecurityInterceptor;
    }

    @Bean
    public LinkedHashMap<RequestMatcher, Collection<ConfigAttribute>> secPatternMap() {
        LinkedHashMap<RequestMatcher, Collection<ConfigAttribute>> patternMap = new LinkedHashMap<RequestMatcher, Collection<ConfigAttribute>>();
    /* For a web app, something like below needs to be added on construction */
//    patternMap.put(new AntPathRequestMatcher("/**"), Arrays.<ConfigAttribute>asList(new SecurityConfig(""+config.get("security.authz.expression"))));
        patternMap.put(new AntPathRequestMatcher("/accessdenied"), Arrays.<ConfigAttribute>asList(new SecurityConfig("permitAll()")));
        return patternMap;
    }

    @Bean
    public SecurityExpressionHandler<FilterInvocation> securityExpressionHandler() {
        SecurityExpressionHandler<FilterInvocation> securityExpressionHandler = new DefaultWebSecurityExpressionHandler();
        return securityExpressionHandler;
    }

    @Bean
    public AccessDecisionManager accessDecisionManager() {
        @SuppressWarnings("rawtypes")
        List<AccessDecisionVoter> voters = Arrays.<AccessDecisionVoter>asList(new RoleVoter(), new WebExpressionVoter());
        AccessDecisionManager accessDecisionManager = new AffirmativeBased(voters);
        return accessDecisionManager;
    }

    @Bean
    public AuthenticationManager authenticationManager() {
        List<AuthenticationProvider> providers = Arrays.<AuthenticationProvider>asList(preAuthenticatedAuthenticationProvider(), kerberosServiceAuthenticationProvider());
        AuthenticationManager authenticationManager = new ProviderManager(providers);
        return authenticationManager;
    }

    @Bean
    public PreAuthenticatedAuthenticationProvider preAuthenticatedAuthenticationProvider() {
        PreAuthenticatedAuthenticationProvider preAuthServiceAuthenticationProvider = new PreAuthenticatedAuthenticationProvider();
        preAuthServiceAuthenticationProvider.setPreAuthenticatedUserDetailsService(authenticationUserDetailsService());
        preAuthServiceAuthenticationProvider.afterPropertiesSet();
        return preAuthServiceAuthenticationProvider;
    }

    @Bean
    public LdapAuthenticationUserDetailsService authenticationUserDetailsService() {
        LdapAuthenticationUserDetailsService authenticationUserDetailsService = new LdapAuthenticationUserDetailsService();
        return authenticationUserDetailsService;
    }

    @Bean
    public KerberosServiceAuthenticationProvider kerberosServiceAuthenticationProvider() {
        KerberosServiceAuthenticationProvider kerberosAuthenticationProvider = new KerberosServiceAuthenticationProvider();
        kerberosAuthenticationProvider.setUserDetailsService(ldapUserDetailsService());
        kerberosAuthenticationProvider.setTicketValidator(ticketValidator());
        try {
            kerberosAuthenticationProvider.afterPropertiesSet();
        } catch (Exception e) {
            throw new SecurityException(e);
        }
        return kerberosAuthenticationProvider;
    }

    @Bean
    public LdapUserDetailsService ldapUserDetailsService() {
        LdapUserDetailsService userDetailsService = new LdapUserDetailsService(ldapUserSearch(), ldapAuthoritiesPopulator());
        return userDetailsService;
    }

    @Bean
    public LdapUserSearch ldapUserSearch() {
        CachingFilterBasedLdapUserSearch userSearch = new CachingFilterBasedLdapUserSearch("" + config.get("ldap.context.base"), "(userPrincipalName={0})", ldapContextSource());
        return userSearch;
    }

    @Bean
    public BaseLdapPathContextSource ldapContextSource() {
        DefaultSpringSecurityContextSource ldapContext = new DefaultSpringSecurityContextSource("" + config.get("ldap.url"));
        ldapContext.setUserDn("" + config.get("ldap.user"));
        ldapContext.setPassword("" + config.get("ldap.pass"));
//    ldapContext.setReferral("follow");
        ldapContext.setReferral("ignore");

        try {
            ldapContext.afterPropertiesSet();
        } catch (Exception e) {
            throw new SecurityException(e);
        }

        BaseLdapPathPoolingContextSourceAdapter ldapPool = new BaseLdapPathPoolingContextSourceAdapter(ldapContext);
        ldapPool.setContextSource(ldapContext);

    /* ldap pool config */
        ldapPool.setDirContextValidator(dirContextValidator());
        ldapPool.setMinIdle(Integer.parseInt("" + config.get("ldap.minIdle")));
        ldapPool.setMaxIdle(Integer.parseInt("" + config.get("ldap.maxIdle")));
        ldapPool.setMaxActive(Integer.parseInt("" + config.get("ldap.maxActive")));
        ldapPool.setMaxTotal(Integer.parseInt("" + config.get("ldap.maxTotal")));
        ldapPool.setMaxWait(Integer.parseInt("" + config.get("ldap.maxWait")));

        ldapPool.setWhenExhaustedAction(Byte.parseByte("" + config.get("ldap.whenExhaustedAction")));

        ldapPool.setTestOnBorrow(Boolean.parseBoolean("" + config.get("ldap.testOnBorrow")));
        ldapPool.setTestOnReturn(Boolean.parseBoolean("" + config.get("ldap.testOnReturn")));
        ldapPool.setTestWhileIdle(Boolean.parseBoolean("" + config.get("ldap.testWhileIdle")));

        ldapPool.setTimeBetweenEvictionRunsMillis(Long.parseLong("" + config.get("ldap.timeBetweenEvictionRunsMillis")));
        ldapPool.setMinEvictableIdleTimeMillis(Long.parseLong("" + config.get("ldap.minEvictableIdleTimeMillis")));
        ldapPool.setNumTestsPerEvictionRun(Integer.parseInt("" + config.get("ldap.numTestsPerEvictionRun")));

        return ldapPool;
    }

    @Bean
    DirContextValidator dirContextValidator() {
        return new DefaultDirContextValidator();
    }

    @Bean
    public LdapAuthoritiesPopulator ldapAuthoritiesPopulator() {
        LdapAuthoritiesPopulator authoritiesPopulator = new DefaultLdapAuthoritiesPopulator(ldapContextSource(), "" + config.get("ldap.context.base"));
        return authoritiesPopulator;
    }

    @Bean
    public KerberosServicePrincipalTicketValidator ticketValidator() {
        KerberosServicePrincipalTicketValidator ticketValidator = new KerberosServicePrincipalTicketValidator();
        ticketValidator.setKerberosServicePrincipal(kerberosServicePrincipal());
        return ticketValidator;
    }

    @Bean
    public KerberosServicePrincipal kerberosServicePrincipal() {
        AbstractJaasKerberosLoginConfiguration jaasLoginConfig = new IbmJaasKerberosClientLoginConfiguration();
        GssKerberosServicePrincipal kerberosServicePrincipal = new GssKerberosServicePrincipal(jaasLoginConfig);
        return kerberosServicePrincipal;
    }

    @Bean
    public AbstractPreAuthenticatedProcessingFilter preAuthAuthenticationFilter() {
        WebsphereX509AuthenticationFilter wasX509AuthenticationFilter = new WebsphereX509AuthenticationFilter();
        wasX509AuthenticationFilter.setAuthenticationManager(authenticationManager());
        wasX509AuthenticationFilter.afterPropertiesSet();
        return wasX509AuthenticationFilter;
    }

    @Bean
    public SpnegoEntryPoint spnegoEntryPoint() {
        SpnegoEntryPoint spnegoEntryPoint = new SpnegoEntryPoint();
        return spnegoEntryPoint;
    }

    @Bean
    public SpnegoAuthenticationProcessingFilter spnegoAuthenticationProcessingFilter() {
        SpnegoAuthenticationProcessingFilter spnegoAuthenticationProcessingFilter = new SpnegoAuthenticationProcessingFilter();
        spnegoAuthenticationProcessingFilter.setAuthenticationManager(authenticationManager());
        SimpleUrlAuthenticationFailureHandler failureHandler = new SimpleUrlAuthenticationFailureHandler();
        failureHandler.setDefaultFailureUrl("/accessdenied");
        spnegoAuthenticationProcessingFilter.setFailureHandler(failureHandler);
        try {
            spnegoAuthenticationProcessingFilter.afterPropertiesSet();
        } catch (Exception e) {
            throw new SecurityException(e);
        }
        return spnegoAuthenticationProcessingFilter;
    }

    @Bean
    public ErrorSendingAccessDeniedHandler accessDeniedHandler() {
        ErrorSendingAccessDeniedHandler accessDeniedHandler = new ErrorSendingAccessDeniedHandler();
        return accessDeniedHandler;
    }

    public ExceptionTranslationFilter exceptionTranslationFilter() {
        ExceptionTranslationFilter exceptionTranslationFilter = new ExceptionTranslationFilter(spnegoEntryPoint());
        exceptionTranslationFilter.setAccessDeniedHandler(accessDeniedHandler());
        exceptionTranslationFilter.afterPropertiesSet();
        return exceptionTranslationFilter;
    }

    @Bean
    public AnonymousAuthenticationFilter anonymousAuthenticationFilter() {
        AnonymousAuthenticationFilter anonymousAuthFilter = new AnonymousAuthenticationFilter("soa");
        anonymousAuthFilter.afterPropertiesSet();
        return anonymousAuthFilter;
    }
}
