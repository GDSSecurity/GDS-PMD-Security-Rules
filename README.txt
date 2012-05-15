GDS PMD Secure Coding Ruleset - Custom ruleset for the open source static analysis tool PMD (http://pmd.sourceforge.net/). The ruleset contains rules intended to identify security violations that map to the 2010 OWASP Top 10 (https://www.owasp.org/index.php/Top_10_2010-Main) application security risks.

Author: Joe Hemler - Gotham Digital Science (labs@gdssecurity.com)
 
Below are instructions for running PMD 4.2.X with the GDS Secure Coding Ruleset.


Basic Usage Steps
-----------------

Before reading the steps below, please first read the official PMD documentation for running PMD from the command-line or as a ANT task.  The following steps supplement the typical instructions for running PMD and should be followed irrespective of whether PMD will be run from the command-line or as a ANT task.

1. Place pmd-gds-1.0.jar on the PMD CLASSPATH

2. For the application source code to be scanned, place libraries and classes normally needed to build it on the PMD CLASSPATH. This provides additional type information to PMD, which makes for more accurate results.

3. Configure PMD to use the GDS Secure Coding Ruleset. Assuming pmd-gds-1.0.jar is on the CLASSPATH, this ruleset will be accessible via "rulesets/GDS/SecureCodingRuleset.xml".

4. Run PMD against application source code and audit the results to determine if a security violation reported by PMD is actually a security vulnerability.

Next Steps
----------

- Refer to the section in this README "Preparing JSP Files for Scanning" if the application source code includes JSP files. 

- Refer to the section in this README "Running PMDTask with the GDS Secure Coding Ruleset" for assistance with running the PMD ANT task with the GDS Secure Coding Ruleset.

- Refer to the file rulesets/GDS/SecureCodingRuleset.xml for information about the types of issues the rules will find and how they work.

- Read and then run the the batch file samples\run_pmd.bat to give the rules a quick test run. 

- Contribute to the project!


Preparing JSP Files for Scanning
--------------------------------
Official PMD documentation states that PMD only supports JSP files that are XHTML-compliant (i.e. JSP Documents / XML syntax). Refer to http://pmd.sourceforge.net/jspsupport.html for additional information on this limitation.

A workaround to this limitation is leveraging JSP pre-compilation using JSP compiler (Jasper) features. Jasper converts JSP files into Java files (.java) and also creates a mapping (i.e. a .smap file) for each .java and .jsp file set. The GDS Secure Coding Ruleset was designed to leverage this functionality. PMD configured with the ruleset can be run against the Java files and when a violation is identified, the .smap file is used to map the violation in the .java file to the .jsp file. The JSP developer can then focus remediation efforts on the JSP file.

Example 1 below is a snippet from apache.org of the recommended jasper2 ANT configuration for pre-compiling JSP files. Example 2 is updated with additional configuration to generate the .java and .smap files need by the GDS Secure Coding Ruleset.
	
	Example 1 - from "http://tomcat.apache.org/tomcat-6.0-doc/jasper-howto.html#Web_Application_Compilation"

	<jasper2 
             validateXml="false" 
             uriroot="${webapp.path}" 
             webXmlFragment="${webapp.path}/WEB-INF/generated_web.xml" 
             outputDir="${webapp.path}/WEB-INF/src" /> 

	Example 2 - the smapSuppressed, smapDumped, and compile options should be configured as shown below in order to scan JSP files with the GDS Secure Coding Ruleset. 

	<jasper2 
             validateXml="false" 
             uriroot="${webapp.path}" 
             webXmlFragment="${webapp.path}/WEB-INF/generated_web.xml" 
             outputDir="${webapp.path}/WEB-INF/src" 
             smapSuppressed="false" 
             smapDumped="true" 
             compile="true"/> 

After the pre-compilation is completed, the outputDir will contain a .java, .class, and .smap file for each JSP file in uriroot. The outputDir should be included as a source code directory to be scanned by PMD with the GDS Secure Coding Ruleset. Additionally, outputDir should be added to the PMD CLASSPATH.


Running PMDTask with the GDS Secure Coding Ruleset
-------------------------------------------------
This section assumes you have already read and followed the directions in the official PMD documentation for "Ant task usage" (http://pmd.sourceforge.net/ant-task.html) as well as the section in this README called "Preparing JSP Files for Scanning". The following is provided to further assist with configuring PMDTask to scan application source code with the GDS Secure Coding Ruleset. 

	<!-- setup the CLASSPATH -->
	<path id="classpath.pmdtask">
		
		<!-- Add paths to JARs normally required to run PMD. -->
		<fileset dir="${pmd.dir.home}\lib">
			<include name="pmd-${pmd.version}.jar" />
		..snip..
		</fileset>
		
		<!-- The following path is required in order to use the GDS Secure Coding Ruleset -->
		<pathelement location="pmd-gds-1.0.jar" />
		
		<!-- Add paths to JARs and classes needed to build application source code. Adding these JARs is recommended when using PMD with the GDS Secure Coding Ruleset -->
		
		<!-- Add paths to relevant application server JARs. For Tomcat, the minimum needed is jasper.jar, servlet-api.jar, and jsp-api.jar. Adding these JARs is recommended when using PMD with the GDS Secure Coding Ruleset -->
				
	</path>
	

	<!-- the directories containing .java files to be scanned -->	
	<property name="JSP_SRC_PATH" value="${webapp.path}/WEB-INF/src"/>
	<property name="JAVA_SRC_PATH" value="${webapp.java.files}"/>
	

	<target name="RunPMD" description="Runs PMD with the GDS Secure Coding Ruleset">
	<record name="PMD.GDS.scan.log" loglevel="verbose" append="false"/>
		<taskdef name="pmd" classname="net.sourceforge.pmd.ant.PMDTask" classpathref="classpath.pmdtask"/>
		<pmd rulesetfiles="rulesets/GDS/SecureCodingRuleset.xml" shortFilenames="false">
			<formatter type="text" toConsole="true" />
			<fileset dir="${JSP_SRC_PATH}">
				<include name="**/*.java" />
			</fileset>
			<fileset dir="${JAVA_SRC_PATH}">
				<include name="**/*.java" />
			</fileset>
		</pmd>	
	</target>


Miscellaneous Notes
------------------
- Unfortunately, the official PMD Eclipse plugin only supports XPath rules out of box. Therefore, GDS Secure Coding Ruleset is not officially supported in Eclipse at this time.

GDS PMD Secure Coding Ruleset is released under the Reciprocal Public License 1.5 (RPL1.5) http://www.opensource.org/licenses/rpl1.5
Copyright (c) 2012 Gotham Digital Science, LLC -- All Rights Reserved 