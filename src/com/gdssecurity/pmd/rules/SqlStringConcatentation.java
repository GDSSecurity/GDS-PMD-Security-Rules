/*
 * This code is licensed under the Reciprocal Public License 1.5 (RPL1.5)http://www.opensource.org/licenses/rpl1.5
 * 
 * Copyright (c) 2012 Gotham Digital Science, LLC -- All Rights Reserved
 *
 */


package com.gdssecurity.pmd.rules;


import java.text.MessageFormat;
import java.util.List;
import java.util.regex.Pattern;

import net.sourceforge.pmd.PropertyDescriptor;
import net.sourceforge.pmd.RuleContext;
import net.sourceforge.pmd.lang.java.ast.ASTAdditiveExpression;
import net.sourceforge.pmd.lang.java.ast.ASTName;
import net.sourceforge.pmd.lang.java.rule.regex.RegexHelper;
import net.sourceforge.pmd.lang.java.symboltable.JavaNameOccurrence;
import net.sourceforge.pmd.lang.rule.properties.StringProperty;
import net.sourceforge.pmd.lang.symboltable.NameOccurrence;

import com.gdssecurity.pmd.Utils;


public class SqlStringConcatentation extends BaseSecurityRule {

    private static final PropertyDescriptor<String> standardSqlRegexDescriptor = new StringProperty(
            "standardsqlregex",
            "regular expression for detecting standard SQL statements",
            "undefined", 1.0F);
    private static final PropertyDescriptor<String> customSqlRegexDescriptor = new StringProperty(
            "customsqlregex",
            "regular expression for detecting custom SQL, such as stored procedures and functions",
            "undefined", 1.0F);


    
    private static Pattern standardSqlRegex = null;
    private static Pattern customSqlRegex = null;

    
    public SqlStringConcatentation() {
    	super();
    	this.propertyDescriptors.add(standardSqlRegexDescriptor);
    	this.propertyDescriptors.add(customSqlRegexDescriptor);

    }
    
    @Override
	protected void init() {
    	super.init();
        if (standardSqlRegex == null) {
            standardSqlRegex = Pattern.compile(
            		getProperty(standardSqlRegexDescriptor), Pattern.CASE_INSENSITIVE | Pattern.MULTILINE);
        }
        
        if (customSqlRegex == null) {
            customSqlRegex = Pattern.compile(
            		getProperty(customSqlRegexDescriptor), Pattern.CASE_INSENSITIVE | Pattern.MULTILINE);
        }
        

    }



    @Override
	public Object visit(ASTAdditiveExpression astAdditiveExpression, Object obj) {
        RuleContext rc = (RuleContext) obj;
        int beginLine = astAdditiveExpression.getBeginLine();
        int endLine = astAdditiveExpression.getEndLine();
        String codeSnippet = Utils.getCodeSnippet(rc.getSourceCodeFilename(), beginLine, endLine);
        boolean match = false;
        
        if (codeSnippet != null && standardSqlRegex != null && RegexHelper.isMatch(standardSqlRegex, codeSnippet)) {
            match = true;
        } else if (codeSnippet != null && customSqlRegex != null && RegexHelper.isMatch(customSqlRegex, codeSnippet)) {
            match = true;
		}

		if (match) {
			List<ASTName> concatenatedVars = astAdditiveExpression.findDescendantsOfType(ASTName.class);

			for (ASTName astName : concatenatedVars) {
				String varName = astName.getImage();
				String varType = Utils.getType(astName, rc, varName);

				if (varType.contains("java.lang.String")) {
					NameOccurrence n = new JavaNameOccurrence(astName, astName.getImage());

					if (astAdditiveExpression.getScope().contains(n)) {
						addSecurityViolation(
								this,
								rc,
								astAdditiveExpression,
								MessageFormat.format(getMessage(), new Object[] { varName, varType,
										varName + " appears to be a method argument" }), "");
					} else {
						addSecurityViolation(
								this,
								rc,
								astAdditiveExpression,
								MessageFormat.format(getMessage(), new Object[] { varName, varType,
										"Check whether " + varName + " contains tainted data" }), "");
					}
				} else if (isUnsafeType(varType)) {
					addSecurityViolation(
							this,
							rc,
							astAdditiveExpression,
							MessageFormat.format(getMessage(), new Object[] { varName, varType,
									varType + " is  tainted data" }), "");
				} else if (isSafeType(varType)) {
					// LOG.finest("Ignoring " + varType +
					// " as this was configured as one of the safe types.");
				} else {
					addSecurityViolation(
							this,
							rc,
							astAdditiveExpression,
							MessageFormat.format(getMessage(), new Object[] { varName, varType,
									"Check whether " + varType + " contains tainted data" }), "");
				}
			}

		}

        return super.visit(astAdditiveExpression, obj);
    }

}
