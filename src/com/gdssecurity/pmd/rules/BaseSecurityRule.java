/*
 * This code is licensed under the Reciprocal Public License 1.5 (RPL1.5)http://www.opensource.org/licenses/rpl1.5
 * 
 * Copyright (c) 2012 Gotham Digital Science, LLC -- All Rights Reserved
 *
 */


package com.gdssecurity.pmd.rules;


import java.io.IOException;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.logging.FileHandler;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.logging.SimpleFormatter;

import net.sourceforge.pmd.PropertyDescriptor;
import net.sourceforge.pmd.Report;
import net.sourceforge.pmd.Rule;
import net.sourceforge.pmd.RuleContext;
import net.sourceforge.pmd.RuleViolation;
import net.sourceforge.pmd.lang.ast.Node;
import net.sourceforge.pmd.lang.java.rule.AbstractJavaRule;
import net.sourceforge.pmd.lang.rule.properties.StringMultiProperty;

import com.gdssecurity.pmd.SecurityRuleViolation;
import com.gdssecurity.pmd.Utils;


public class BaseSecurityRule extends AbstractJavaRule {
    private static final Logger LOG = Logger.getLogger(
            "com.gdssecurity.pmd.rules");
    private static FileHandler fileHandler; 

	protected static HashSet<String> sources = new HashSet<String>();
	
	
	public BaseSecurityRule() {
		super();
		this.propertyDescriptors.add(sourceDescriptor);
	}


    private static PropertyDescriptor<String[]> sourceDescriptor = new StringMultiProperty(
            "sources", "TODO",
            new String[] {
        "javax.servlet.http.HttpServletRequest.getParameter" }, 1.0f, '|');
	
    protected HashSet<String> getDefaultSources() {
        return sources;
    }
    
    @Override
	public void start(RuleContext ctx) {
        String methodMsg = "AbstractSecurityRule::start";

        LOG.fine(methodMsg);
        if (sources.size() < 1) {
            sources = Utils.arrayAsHashSet(getProperty(sourceDescriptor));
        }
    }
	
    @SuppressWarnings({ "unchecked", "rawtypes" })
	@Override
	public void apply(List list, RuleContext rulecontext) {
        String methodMsg = "AbstractSecurityRule::apply";

        LOG.fine(methodMsg);
        super.apply(list, rulecontext);
    }

    public static Logger getLogger() {

        if (LOG.getLevel() == null) {
            LOG.setLevel(Level.OFF);
        }
    	
        if (!LOG.getLevel().equals(Level.OFF)) {
            try {
                if (fileHandler == null) {
                    LOG.setUseParentHandlers(false);
                    fileHandler = new FileHandler("PMD.GDS.log");
                    fileHandler.setFormatter(new SimpleFormatter());
                    LOG.addHandler(fileHandler);
                }
            } catch (SecurityException e) {
				
                e.printStackTrace();
            } catch (IOException e) {
				
                e.printStackTrace();
            }
        }
  	
        return LOG;
    }
    
    protected final void addSecurityViolation(Rule rule, RuleContext ctx, Node simpleNode, String message, String variableName, String type) {
        Report rpt = ctx.getReport();       
        boolean isNewSecurityViolation = true;
    	
        if (rpt.getViolationTree().size() > 0) {
            for (Iterator<RuleViolation> i = rpt.iterator(); i.hasNext();) {
                RuleViolation ruleViolation = i.next();
	    		
                if (ruleViolation instanceof SecurityRuleViolation) {
                    SecurityRuleViolation secRuleViolation = (SecurityRuleViolation) ruleViolation;	    		
			        	
                    if (rule.getName() == secRuleViolation.getRule().getName()
                            && ctx.getSourceCodeFilename()
                                    == secRuleViolation.getJavaFileName()
                                    && simpleNode.getBeginLine()
                                            == secRuleViolation.getJavaBeginLine()
                                            && simpleNode.getEndLine()
                                                    == secRuleViolation.getJavaEndLine()) {
                        isNewSecurityViolation = false;
                    }
                }
            }   
        }
    	
        if (isNewSecurityViolation) { 
        	
            LOG.log(Level.FINE,
                    "*** Adding security violation to report for rule "
                    + rule.getName() + " in " + ctx.getSourceCodeFilename()
                    + " Begin line: " + simpleNode.getBeginLine()
                    + " End line: " + simpleNode.getEndLine()
                    + " Violation message: " + message);
            rpt.addRuleViolation(
                    new SecurityRuleViolation(rule, ctx, simpleNode, message,
                    variableName, type));

        } else {
            LOG.log(Level.FINE,
                    "*** Duplicate security violation in report for rule "
                    + rule.getName() + " in " + ctx.getSourceCodeFilename()
                    + " Begin line: " + simpleNode.getBeginLine()
                    + " End line: " + simpleNode.getEndLine()
                    + " Violation will not be added to report");
        }   	
    }
   
    
}
