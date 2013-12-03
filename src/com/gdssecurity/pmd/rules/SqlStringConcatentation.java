/*
 * This code is licensed under the Reciprocal Public License 1.5 (RPL1.5)http://www.opensource.org/licenses/rpl1.5
 * 
 * Copyright (c) 2012 Gotham Digital Science, LLC -- All Rights Reserved
 *
 */


package com.gdssecurity.pmd.rules;


import java.text.MessageFormat;
import java.util.*;
import java.util.logging.Logger;
import java.util.regex.Pattern;

import com.gdssecurity.pmd.Utils;

import net.sourceforge.pmd.PropertyDescriptor;
import net.sourceforge.pmd.RuleContext;
import net.sourceforge.pmd.ast.ASTAdditiveExpression;
import net.sourceforge.pmd.ast.ASTName;
import net.sourceforge.pmd.properties.StringProperty;
import net.sourceforge.pmd.rules.regex.RegexHelper;
import net.sourceforge.pmd.symboltable.NameOccurrence;


public class SqlStringConcatentation extends BaseSecurityRule {

    private static final Logger LOG = getLogger();
    private static final PropertyDescriptor standardSqlRegexDescriptor = new StringProperty(
            "standardsqlregex",
            "regular expression for detecting standard SQL statements",
            "undefined", 1.0F);
    private static final PropertyDescriptor customSqlRegexDescriptor = new StringProperty(
            "customsqlregex",
            "regular expression for detecting custom SQL, such as stored procedures and functions",
            "undefined", 1.0F);
    private static final PropertyDescriptor insecureTypesDescriptor = new StringProperty(
            "insecureTypes",
            "types that could create a potential SQLi exposure when concatenated to a SQL statement",
            new String[] { "\"java.lang.String\"" }, 1.0f, '|');

    // Ignoring Numeric types by default
    private static final PropertyDescriptor safeTypesDescriptor = new StringProperty(
            "safeTypes",
            "types that may be considered safe to ignore.",
            new String[] { "\"java.lang.Integer\"" }, 1.0f, '|');
    
    private static Pattern standardSqlRegex = null;
    private static Pattern customSqlRegex = null;
    private static HashSet<String> insecureTypes = null;
    private static HashSet<String> safeTypes = null;
    
    protected void init() {
        if (standardSqlRegex == null) {
            standardSqlRegex = Pattern.compile(
                    getStringProperty(standardSqlRegexDescriptor), Pattern.CASE_INSENSITIVE | Pattern.MULTILINE);
        }
        
        if (customSqlRegex == null) {
            customSqlRegex = Pattern.compile(
                    getStringProperty(customSqlRegexDescriptor), Pattern.CASE_INSENSITIVE | Pattern.MULTILINE);
        }
        
        if (insecureTypes == null) {
            insecureTypes = Utils.arrayAsHashSet(
                    getStringProperties(insecureTypesDescriptor));
        }

        if (safeTypes == null) {
            safeTypes = Utils.arrayAsHashSet(
                    getStringProperties(safeTypesDescriptor));
        }
    }

    public void apply(List list, RuleContext rulecontext) {
        LOG.finest("Analyzing file " + rulecontext.getSourceCodeFilename());
        init();
        super.apply(list, rulecontext);
    }

    public Object visit(ASTAdditiveExpression astAdditiveExpression, Object obj) {
        RuleContext rc = (RuleContext) obj;
        int beginLine = astAdditiveExpression.getBeginLine();
        int endLine = astAdditiveExpression.getEndLine();
        String codeSnippet = Utils.getCodeSnippet(rc.getSourceCodeFilename(),
                beginLine, endLine);
        boolean match = false;
        
        if (codeSnippet != null && standardSqlRegex != null
                && RegexHelper.isMatch(standardSqlRegex, codeSnippet)) {
            match = true;
            LOG.finest(
                    "SQL regex match on line(s) " + beginLine + "-" + endLine
                    + " with pattern " + standardSqlRegex.toString());
        } else if (codeSnippet != null && customSqlRegex != null
                && RegexHelper.isMatch(customSqlRegex, codeSnippet)) {
            match = true;
            LOG.finest(
                    "SQL regex match on line(s) " + beginLine + "-" + endLine
                    + " with pattern " + customSqlRegex.toString());
        }
        
        if (match) {
            List<ASTName> concatentatedVars = (ArrayList<ASTName>) astAdditiveExpression.findChildrenOfType(
                    ASTName.class);

            if (concatentatedVars != null) {
                Iterator<ASTName> iterator = concatentatedVars.iterator();

                while (iterator.hasNext()) {
                    ASTName astName = iterator.next();
                    String varName = astName.getImage();
                    String varType = Utils.getType(astName, rc, varName);

                    if (varType.indexOf("java.lang.String") != -1) {                        
                        NameOccurrence n = new NameOccurrence(astName,
                                astName.getImage());

                        if (astAdditiveExpression.getScope().getEnclosingMethodScope().contains(
                                n)) {
                            addSecurityViolation(this, rc, astAdditiveExpression,
                                    MessageFormat.format(getMessage(),
                                    new Object[] {
                                varName, "java.lang.String",
                                varName + " appears to be a method argument"}),
                                    "",
                                    "");
                        } else {
                            addSecurityViolation(this, rc, astAdditiveExpression,
                                    MessageFormat.format(getMessage(),
                                    new Object[] {
                                varName, "java.lang.String",
                                "Check whether " + varName
                                        + " contains tainted data"}),
                                    "",
                                    "");
                        }
                    } else if (insecureTypes.contains(varType)) {
                        addSecurityViolation(this, rc, astAdditiveExpression,
                                MessageFormat.format(getMessage(),
                                new Object[] {
                            varName, varType,
                            varType + " is  tainted data"}),
                                "",
                                "");
                    } else if (safeTypes.contains(varType)) {
                            LOG.finest("Ignoring " + varType + " as this was configured as one of the safe types.");
                    } else {
                        addSecurityViolation(this, rc, astAdditiveExpression,
                                MessageFormat.format(getMessage(),
                                new Object[] {
                            varName, varType,
                            "Check whether " + varType
                                    + " contains tainted data"}),
                                "",
                                "");
                    }
                }
            } else {
                LOG.finest("Concatenation of SQL strings detected. This does not appear to introduce a potential SQL Injection vulnerability; however, consider a parameterized command and moving the SQL into a stored procedure");
            }
        }
        
        return super.visit(astAdditiveExpression, obj);
    }

}
