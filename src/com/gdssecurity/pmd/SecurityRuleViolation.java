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

import net.sourceforge.pmd.Rule;
import net.sourceforge.pmd.RuleContext;
import net.sourceforge.pmd.RuleViolation;
import net.sourceforge.pmd.lang.ast.Node;
import net.sourceforge.pmd.lang.java.ast.ASTClassOrInterfaceBodyDeclaration;
import net.sourceforge.pmd.lang.java.ast.ASTClassOrInterfaceDeclaration;
import net.sourceforge.pmd.lang.java.ast.ASTCompilationUnit;
import net.sourceforge.pmd.lang.java.ast.ASTFormalParameter;
import net.sourceforge.pmd.lang.java.ast.ASTLocalVariableDeclaration;
import net.sourceforge.pmd.lang.java.ast.ASTMethodDeclaration;
import net.sourceforge.pmd.lang.java.ast.ASTTypeDeclaration;
import net.sourceforge.pmd.lang.java.ast.CanSuppressWarnings;

import com.gdssecurity.pmd.smap.SmapFileReader;
import com.gdssecurity.pmd.smap.SmapResolver;


public class SecurityRuleViolation implements Comparator<RuleViolation>, RuleViolation {
    
    private Rule rule;
    private String description;
    private String fileName; 

    private String className;
    private String methodName;
    private String variableName;

    private String packageName;
    private int beginLine; 
    private int endLine; 

    private int beginColumn;
    private int endColumn;
    private boolean isSuppressed;
	
    private String javaFileName; 
    private int javaBeginLine; 
    private int javaEndLine; 
   
    @Override
	public int compare(RuleViolation r1, RuleViolation r2) {
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
    
    	
    public SecurityRuleViolation(Rule rule, RuleContext ctx, Node node, String specificMsg, String variable) {
        this.rule = rule;
        this.javaFileName = ctx.getSourceCodeFilename();
        this.variableName = variable;
       
        if (node != null) {
            if (node.getFirstParentOfType(ASTClassOrInterfaceDeclaration.class)
                    == null) {
	            
                this.className = "";
            } else {            	
            	this.className = node.getFirstParentOfType(ASTClassOrInterfaceDeclaration.class).getImage();
            }
	        
            String qualifiedName = null;
            List<ASTClassOrInterfaceDeclaration> parents = node.getParentsOfType(
                    ASTClassOrInterfaceDeclaration.class);

            for (ASTClassOrInterfaceDeclaration parent : parents) {
                if (qualifiedName == null) {
                    qualifiedName = parent.getImage();
                } else {
                    qualifiedName = parent.getImage() + "$" + qualifiedName;
                }
            }
            ASTMethodDeclaration method = node.getFirstParentOfType(ASTMethodDeclaration.class);
            if (method != null) {
            	this.methodName = method.getMethodName();
            }
            ASTCompilationUnit compilationUnit = node.getFirstParentOfType(ASTCompilationUnit.class);
            if (compilationUnit != null && compilationUnit.getPackageDeclaration()!= null){
            	this.packageName = compilationUnit.getPackageDeclaration().getPackageNameImage();
            }


            this.javaBeginLine = node.getBeginLine(); 
            this.javaEndLine = node.getEndLine(); 

            if (this.javaFileName.indexOf("WEB-INF") > 0) {
                int webRootDirPos = this.javaFileName.indexOf("WEB-INF");
                String webRootDirName = this.javaFileName.substring(0,
                        webRootDirPos);
				
                int dot = this.javaFileName.lastIndexOf(".");
                String smapFileName = this.javaFileName.substring(0, dot)
                        + ".class.smap";
                SmapFileReader r = new SmapFileReader(new File(smapFileName));
                SmapResolver resolver = new SmapResolver(r);
				
                this.fileName = webRootDirName
                        + resolver.getJspFileName(this.javaBeginLine, 0); 
                this.beginLine = resolver.unmangle(this.javaBeginLine, 0); 
                this.endLine = resolver.unmangle(this.javaEndLine, 0); 
            } else {
                this.fileName = this.javaFileName;
                this.beginLine = this.javaBeginLine;
                this.endLine = this.javaEndLine;
            }

            if (specificMsg == "") {
                this.description = "No message for rule violation. Code snippet: "
                        + Utils.getCodeSnippet(this.fileName, this.beginLine, this.endLine);
            } else {
                this.description = specificMsg;
            }
	
            List<Node> parentTypes = new ArrayList<Node>(
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
                    Node n = node.jjtGetChild(i);

                    if (n instanceof ASTTypeDeclaration) {
                        parentTypes.add(n);
                    }
                }
            }
            for (Node parentType : parentTypes) {
                CanSuppressWarnings t = (CanSuppressWarnings) parentType;

                if (t.hasSuppressWarningsAnnotationFor(getRule())) {
                    this.isSuppressed = true;
                }
            }
        } else {
            this.className = "";
            this.methodName = "";
            this.packageName = "";
            this.fileName = "";
        }
    }

    @Override
	public Rule getRule() {
        return this.rule;
    }
	
    @Override
	public boolean isSuppressed() {
        return this.isSuppressed;
    }
	
    @Override
	public int getBeginColumn() {
        return this.beginColumn;
    }
	
    @Override
	public int getEndColumn() {
        return this.endColumn;
    }
	
    @Override
	public String getDescription() {
        return this.description;
    }
	
    @Override
	public String getFilename() {
        return this.fileName;
    }
	
    @Override
	public String getClassName() {
        return this.className;
    }
	
    @Override
	public String getMethodName() {
        return this.methodName;
    }
	
    @Override
	public String getPackageName() {
        return this.packageName;
    }
	
    @Override
	public int getBeginLine() {
        return this.beginLine;
    }
	
    @Override
	public int getEndLine() {
        return this.endLine;
    }
	
    @Override
	public String getVariableName() {
        return this.variableName;
    }
	
    @Override
    public String toString() {
        return getFilename() + ":" + getRule() + ":" + getDescription() + ":"
                + this.beginLine;
    }
	
    public int getJavaBeginLine() {
        return this.javaBeginLine;
    }
	
    public int getJavaEndLine() {
        return this.javaEndLine;
    }
    
    public String getJavaFileName() {
        return this.javaFileName;
    }
    

}
