package com.gdssecurity.pmd;

import net.sourceforge.pmd.PMD;
import net.sourceforge.pmd.PMDConfiguration;
import net.sourceforge.pmd.cli.PMDCommandLineInterface;
import net.sourceforge.pmd.cli.PMDParameters;


public class PMDRunner {

	
	public static int run(String directory) throws Exception {
		int violations = run(
				new String[] {"-d", directory , "-R", "rulesets/GDS/SecureCoding.xml", "-f", "text", "-language", "java" }
		);
		return violations;
	}
	
	  public static int run(String[] args) throws Exception {
	        final PMDParameters params = PMDCommandLineInterface.extractParameters(new PMDParameters(), args, "pmd");
	        final PMDConfiguration configuration = PMDParameters.transformParametersIntoConfiguration(params);


	        try {
	            int violations = PMD.doPMD(configuration);
	            return violations;
	        } catch (Exception e) {
	        	throw e;
	        }
	    }
}
