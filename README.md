# JSec - A Java Security Library

JSec is a Java security library built atop [Spring Security](http://projects.spring.io/spring-security/). The original version was primarily developed to support delegated Kerberos in a Java/JEE environment. Java application servers generally handle Kerberos authentication at a single point well, but do not easily allow for delegating a calling principal's backend identity to downstream resources. JSec supports this. That is, if accessing additional Kerberos protected services, JSec will get a new TGS ticket for that Kerberos service and the call will be made in the context of the initial calling principal. The process can be continued ad infinitum. In a Microsoft Networked environment, all can be recorded in Active Directory making audit and traceability easier.

JSec is built on top of Spring Security and examples are provided that show how both X.509 client certificates and Kerberos can be implemented as authentication mechanisms similar to the [UNIX Pluggable Authentication Module](https://en.wikipedia.org/wiki/Pluggable_authentication_module) pattern. Adding other authentication providers such as [SAML](http://projects.spring.io/spring-security-saml/) and/or [OAuth 2.0](http://projects.spring.io/spring-security-oauth/docs/oauth2.html) should be relatively easy. The authorization scheme is pluggable as well.  

## Kerberos Setup

A Server Principal Name needs to be setup in a directory or similar for every instance of this framework. Some of the best docs on this are from Microsoft for example, [kb929650](https://support.microsoft.com/en-us/kb/929650) and [ms942980](https://msdn.microsoft.com/en-us/library/ms942980.aspx)

There is an example `/etc/kerberos_spn_script.txt` that creates an SPN and outputs a keytab. A keytab is needed by the Java SPN.

Most of the JAAS stuff is handled programmatically, but you may need an [`/etc/krb5.conf`](http://web.mit.edu/kerberos/krb5-1.13/doc/admin/conf_files/krb5_conf.html) file depending on your use case. There is an example one at `/src/test/resources/krb5.conf`

If testing, you may need to use [kinit](http://web.mit.edu/kerberos/krb5-1.12/doc/user/user_commands/kinit.html) to seed a TGT cache. There is an example `kinit` commmand at `/src/test/resources/kinit.cmd`

Sorry, I've been too lazy to properly setup a Kerberos environment on my local Mac to provide a comprehensive test case. #TODO

## Alternatives

[Apache Kerby](http://directory.apache.org/kerby/) did not exist when the original version of this was written. It looks like a well implemented implementation of Kerberos for Java that is worth investigating. Kerby is part of the [Apache Directory](http://directory.apache.org/) project allowing one to stand up a full non Microsoft based Network Operating System.
