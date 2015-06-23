/*
 * This code is licensed under the Reciprocal Public License 1.5 (RPL1.5)http://www.opensource.org/licenses/rpl1.5
 * 
 * Copyright (c) 2012 Gotham Digital Science, LLC -- All Rights Reserved
 *
 */


package com.gdssecurity.pmd.rules;



import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

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

	protected static Set<String> sources = new HashSet<String>();
	
	
    private static PropertyDescriptor<String[]> sourceDescriptor = new StringMultiProperty(
            "sources", "TODO",
            new String[] {
        "javax.servlet.http.HttpServletRequest.getParameter" }, 1.0f, '|');
	
	public BaseSecurityRule() {
		super();
		this.propertyDescriptors.add(sourceDescriptor);
	}



	
    protected Set<String> getDefaultSources() {
        return sources;
    }
    
    @Override
	public void start(RuleContext ctx) {
        if (sources.isEmpty()) {
            sources = Utils.arrayAsSet(getProperty(sourceDescriptor));
        }
    }
	
	@Override
	public void apply(List<? extends Node> list, RuleContext rulecontext) {
        super.apply(list, rulecontext);
    }


    
    protected final void addSecurityViolation(Rule rule, RuleContext ctx, Node simpleNode, String message, String variableName) {
        Report rpt = ctx.getReport();       
        boolean isNewSecurityViolation = true;
    	
        if (rpt.getViolationTree().size() > 0) {
            for (Iterator<RuleViolation> i = rpt.iterator(); i.hasNext();) {
                RuleViolation ruleViolation = i.next();
	    		
                if (ruleViolation instanceof SecurityRuleViolation) {
                    SecurityRuleViolation secRuleViolation = (SecurityRuleViolation) ruleViolation;	    		
			        	
                    if (rule.getName().equals(secRuleViolation.getRule().getName())
                            && ctx.getSourceCodeFilename().equals(secRuleViolation.getJavaFileName())
                            && simpleNode.getBeginLine() == secRuleViolation.getJavaBeginLine()
                            && simpleNode.getEndLine()  == secRuleViolation.getJavaEndLine()) {
                        isNewSecurityViolation = false;
                    }
                }
            }   
        }
    	
        if (isNewSecurityViolation) {            
            rpt.addRuleViolation(new SecurityRuleViolation(rule, ctx, simpleNode, message, variableName));
        } 	
    }
   
    
}
