@echo off

set PMD_HOME=H:\Demo\PMD\pmd-bin-4.2.5\pmd-4.2.5
set CATALINA_HOME=C:\tomcat\apache-tomcat-6.0.29
set CLASSPATH=%CLASSPATH%;..\lib\pmd-gds-1.0.jar;%CATALINA_HOME%\lib\*;gds\WebContent\WEB-INF\classes;juliet-2010-12\antbuild
			
set JSP_SRC_PATH=gds\WebContent\WEB-INF\classes
set JAVA_SRC_PATH=gds\src
set JULIET_SRC_PATH=juliet-2010-12\src

%PMD_HOME%\bin\pmd.bat -targetjdk 1.6 -reportfile report.html %JSP_SRC_PATH%,%JAVA_SRC_PATH%,%JULIET_SRC_PATH% html "rulesets/GDS/SecureCodingRuleset.xml"


rem # File Line Problem 
rem 1 \samples\gds\WebContent\test/XSS/XSS1.jsp 10 Cross-Site Scripting (Reflected) 
rem 2 \samples\gds\WebContent\test/XSS/XSS2.jsp 13 Cross-Site Scripting (Reflected) 
rem 3 \samples\gds\src\test\com\gdssecurity\pmd\webapp\servlet\TestRedirectServlet.java 15 Unvalidated Redirect 
rem 4 \samples\gds\src\test\com\gdssecurity\pmd\webapp\servlet\TestSqliServlet.java 28 id of type java.lang.String concatenated to SQL string creating a possible SQL Injection vulnerability. Additional information: Check whether id contains tainted data. 
rem 5 \samples\gds\src\test\com\gdssecurity\pmd\webapp\servlet\TestSqliServlet.java 32 Sql Injection 
rem 6 \samples\gds\src\test\com\gdssecurity\pmd\webapp\servlet\TestXSSServlet.java 30 Cross-Site Scripting (Reflected) 
rem 7 \samples\gds\src\test\com\gdssecurity\pmd\webapp\servlet\authz\TestRoleAuthZServlet.java 25 Missing Or Incorrect Authorization 
rem 8 \samples\gds\src\test\com\gdssecurity\pmd\webapp\servlet\authz\TestRoleAuthZServlet.java 32 Missing Or Incorrect Authorization 
rem 9 \samples\juliet-2010-12\src\testcases\CWE327_Use_Broken_Crypto\CWE327_Use_Broken_Crypto__basic_01.java 45 Insecure Cryptographic Algorithm 
rem 10 \samples\juliet-2010-12\src\testcases\CWE328_Reversible_One_Way_Hash\CWE328_Reversible_One_Way_Hash__basic_01.java 32 Insecure Cryptographic Algorithm 

		