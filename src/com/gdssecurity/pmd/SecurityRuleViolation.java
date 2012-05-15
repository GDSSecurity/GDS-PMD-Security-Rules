/*
 * This code is licensed under the Reciprocal Public License 1.5 (RPL1.5)http://www.opensource.org/licenses/rpl1.5
 * 
 * Copyright (c) 2012 Gotham Digital Science, LLC -- All Rights Reserved
 *
 */


package com.gdssecurity.pmd;


import java.io.File;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

import com.gdssecurity.pmd.smap.SmapFileReader;
import com.gdssecurity.pmd.smap.SmapResolver;

import net.sourceforge.pmd.IRuleViolation;
import net.sourceforge.pmd.Rule;
import net.sourceforge.pmd.RuleContext;
import net.sourceforge.pmd.RuleViolation;
import net.sourceforge.pmd.ast.ASTClassOrInterfaceBodyDeclaration;
import net.sourceforge.pmd.ast.ASTClassOrInterfaceDeclaration;
import net.sourceforge.pmd.ast.ASTCompilationUnit;
import net.sourceforge.pmd.ast.ASTFieldDeclaration;
import net.sourceforge.pmd.ast.ASTFormalParameter;
import net.sourceforge.pmd.ast.ASTLocalVariableDeclaration;
import net.sourceforge.pmd.ast.ASTMethodDeclaration;
import net.sourceforge.pmd.ast.ASTTypeDeclaration;
import net.sourceforge.pmd.ast.ASTVariableDeclaratorId;
import net.sourceforge.pmd.ast.CanSuppressWarnings;
import net.sourceforge.pmd.ast.SimpleNode;


public class SecurityRuleViolation implements Comparator<IRuleViolation>, IRuleViolation {
    
    private Rule rule;
    private String description;
    private String fileName; 

    private String className;
    private String methodName;
    private String variableName;
    private String type;
    private String packageName;
    private int beginLine; 
    private int endLine; 

    private int beginColumn;
    private int endColumn;
    private boolean isSuppressed;
	
    private String javaFileName; 
    private int javaBeginLine; 
    private int javaEndLine; 
   
    public int compare(IRuleViolation r1, IRuleViolation r2) {
        if (!r1.getFilename().equals(r2.getFilename())) {
            return r1.getFilename().compareTo(r2.getFilename());
        }

        if (r1.getBeginLine() != r2.getBeginLine()) {
            return r1.getBeginLine() - r2.getBeginLine();
        }

        if (r1.getDescription() != null && r2.getDescription() != null
                && !r1.getDescription().equals(r2.getDescription())) {
            return r1.getDescription().compareTo(r2.getDescription());
        }

        if (r1.getBeginLine() == r2.getBeginLine()) {
            return 1;
        }

        return r1.getBeginLine() - r2.getBeginLine();
    }
    
    public SecurityRuleViolation(Rule rule, RuleContext ctx, SimpleNode node, String specificMsg, String variable, String type) {

        this.rule = rule;
        this.javaFileName = ctx.getSourceCodeFilename();
        this.variableName = variable;
        this.type = type;
       
        if (node != null) {
            if (node.getFirstParentOfType(ASTClassOrInterfaceDeclaration.class)
                    == null) {
	            
                className = "";
            } else {
	            
                className = node.getScope().getEnclosingClassScope().getClassName()
                        == null
                                ? ""
                                : node.getScope().getEnclosingClassScope().getClassName();
            }
	        
            String qualifiedName = null;
            List<ASTClassOrInterfaceDeclaration> parents = node.getParentsOfType(
                    ASTClassOrInterfaceDeclaration.class);

            for (ASTClassOrInterfaceDeclaration parent : parents) {
                if (qualifiedName == null) {
                    qualifiedName = parent.getScope().getEnclosingClassScope().getClassName();
                } else {
                    qualifiedName = parent.getScope().getEnclosingClassScope().getClassName()
                            + "$" + qualifiedName;
                }
            }
	        
            if (!"net.sourceforge.pmd.symboltable.SourceFileScope".equals(
                    node.getScope().getClass().getName())) {
                className = node.getScope().getEnclosingClassScope().getClassName()
                        == null
                                ? ""
                                : qualifiedName;
            }
	        
            methodName = node.getFirstParentOfType(ASTMethodDeclaration.class)
                    == null
                            ? ""
                            : node.getScope().getEnclosingMethodScope().getName();
	
            packageName = node.getScope().getEnclosingSourceFileScope().getPackageName()
                    == null
                            ? ""
                            : node.getScope().getEnclosingSourceFileScope().getPackageName();
	
            javaBeginLine = node.getBeginLine(); 
            javaEndLine = node.getEndLine(); 

            if (this.javaFileName.indexOf("WEB-INF") > 0) {
                int webRootDirPos = this.javaFileName.indexOf("WEB-INF");
                String webRootDirName = this.javaFileName.substring(0,
                        webRootDirPos);
				
                int dot = this.javaFileName.lastIndexOf(".");
                String smapFileName = this.javaFileName.substring(0, dot)
                        + ".class.smap";
                SmapFileReader r = new SmapFileReader(new File(smapFileName));
                SmapResolver resolver = new SmapResolver(r);
				
                fileName = webRootDirName
                        + resolver.getJspFileName(javaBeginLine, 0); 
                beginLine = resolver.unmangle(javaBeginLine, 0); 
                endLine = resolver.unmangle(javaEndLine, 0); 
            } else {
                fileName = javaFileName;
                beginLine = javaBeginLine;
                endLine = javaEndLine;
            }

            if (specificMsg == "") {
                this.description = "No message for rule violation. Code snippet: "
                        + Utils.getCodeSnippet(fileName, beginLine, endLine);
            } else {
                this.description = specificMsg;
            }
	
            List<SimpleNode> parentTypes = new ArrayList<SimpleNode>(
                    node.getParentsOfType(ASTTypeDeclaration.class));

            if (node instanceof ASTTypeDeclaration) {
                parentTypes.add(node);
            }
            parentTypes.addAll(
                    node.getParentsOfType(
                            ASTClassOrInterfaceBodyDeclaration.class));
            if (node instanceof ASTClassOrInterfaceBodyDeclaration) {
                parentTypes.add(node);
            }
            parentTypes.addAll(node.getParentsOfType(ASTFormalParameter.class));
            if (node instanceof ASTFormalParameter) {
                parentTypes.add(node);
            }
            parentTypes.addAll(
                    node.getParentsOfType(ASTLocalVariableDeclaration.class));
            if (node instanceof ASTLocalVariableDeclaration) {
                parentTypes.add(node);
            }
            if (node instanceof ASTCompilationUnit) {
                for (int i = 0; i < node.jjtGetNumChildren(); i++) {
                    SimpleNode n = (SimpleNode) node.jjtGetChild(i);

                    if (n instanceof ASTTypeDeclaration) {
                        parentTypes.add(n);
                    }
                }
            }
            for (SimpleNode parentType : parentTypes) {
                CanSuppressWarnings t = (CanSuppressWarnings) parentType;

                if (t.hasSuppressWarningsAnnotationFor(getRule())) {
                    isSuppressed = true;
                }
            }
        } else {
            className = "";
            methodName = "";
            packageName = "";
            fileName = "";
        }
    }

    public Rule getRule() {
        return rule;
    }
	
    public boolean isSuppressed() {
        return this.isSuppressed;
    }
	
    public int getBeginColumn() {
        return beginColumn;
    }
	
    public int getEndColumn() {
        return endColumn;
    }
	
    public String getDescription() {
        return description;
    }
	
    public String getFilename() {
        return fileName;
    }
	
    public String getClassName() {
        return className;
    }
	
    public String getMethodName() {
        return methodName;
    }
	
    public String getPackageName() {
        return packageName;
    }
	
    public int getBeginLine() {
        return beginLine;
    }
	
    public int getEndLine() {
        return endLine;
    }
	
    public String getVariableName() {
        return variableName;
    }
	
    @Override
    public String toString() {
        return getFilename() + ":" + getRule() + ":" + getDescription() + ":"
                + beginLine;
    }
	
    public int getJavaBeginLine() {
        return javaBeginLine;
    }
	
    public int getJavaEndLine() {
        return javaEndLine;
    }
    
    public String getJavaFileName() {
        return javaFileName;
    }
    
    public String getType() {
        return type;
    }
}
