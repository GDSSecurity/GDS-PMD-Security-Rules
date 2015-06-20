/*
 * This code is licensed under the Reciprocal Public License 1.5 (RPL1.5)http://www.opensource.org/licenses/rpl1.5
 * 
 * Copyright (c) 2012 Gotham Digital Science, LLC -- All Rights Reserved
 *
 */


package com.gdssecurity.pmd.rules.dfa;


import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

import net.sourceforge.pmd.PropertyDescriptor;
import net.sourceforge.pmd.RuleContext;
import net.sourceforge.pmd.lang.ast.Node;
import net.sourceforge.pmd.lang.dfa.DataFlowNode;
import net.sourceforge.pmd.lang.dfa.NodeType;
import net.sourceforge.pmd.lang.dfa.VariableAccess;
import net.sourceforge.pmd.lang.dfa.pathfinder.CurrentPath;
import net.sourceforge.pmd.lang.dfa.pathfinder.DAAPathFinder;
import net.sourceforge.pmd.lang.dfa.pathfinder.Executable;
import net.sourceforge.pmd.lang.java.ast.ASTAdditiveExpression;
import net.sourceforge.pmd.lang.java.ast.ASTArgumentList;
import net.sourceforge.pmd.lang.java.ast.ASTArguments;
import net.sourceforge.pmd.lang.java.ast.ASTAssignmentOperator;
import net.sourceforge.pmd.lang.java.ast.ASTClassOrInterfaceDeclaration;
import net.sourceforge.pmd.lang.java.ast.ASTClassOrInterfaceType;
import net.sourceforge.pmd.lang.java.ast.ASTConditionalExpression;
import net.sourceforge.pmd.lang.java.ast.ASTConstructorDeclaration;
import net.sourceforge.pmd.lang.java.ast.ASTExpression;
import net.sourceforge.pmd.lang.java.ast.ASTFormalParameter;
import net.sourceforge.pmd.lang.java.ast.ASTMethodDeclaration;
import net.sourceforge.pmd.lang.java.ast.ASTName;
import net.sourceforge.pmd.lang.java.ast.ASTPrimaryExpression;
import net.sourceforge.pmd.lang.java.ast.ASTStatementExpression;
import net.sourceforge.pmd.lang.java.ast.ASTType;
import net.sourceforge.pmd.lang.java.ast.ASTVariableDeclarator;
import net.sourceforge.pmd.lang.java.ast.ASTVariableDeclaratorId;
import net.sourceforge.pmd.lang.rule.properties.StringMultiProperty;

import org.jaxen.JaxenException;

import com.gdssecurity.pmd.Utils;
import com.gdssecurity.pmd.rules.BaseSecurityRule;


public class DfaSecurityRule extends BaseSecurityRule  implements Executable {
    private static final Logger LOG = getLogger();
	
    private LinkedList<String> currentPathTaintedVariables;
	
	
    private PropertyDescriptor<String[]> sourceDescriptor = new StringMultiProperty("sources",
            "TODO",
            new String[] {
        "javax.servlet.http.HttpServletRequest.getParameter" }, 1.0f, '|');
    private HashSet<String> sinks;

    private PropertyDescriptor<String[]> sinkDescriptor = new StringMultiProperty("sinks", "TODO",
            new String[] { "" }, 1.0f, '|');

    private RuleContext rc;
    private int methodDataFlowCount;
    private String methodName = "";
    private int methodNumOfDataFlows;
	
    private List<DataFlowNode> additionalDataFlowNodes = new ArrayList<DataFlowNode>();
	
    private static final int MAX_DATAFLOWS = 1000;
    
    public DfaSecurityRule () {
    	super();
    	this.propertyDescriptors.add(this.sourceDescriptor);
    	this.propertyDescriptors.add(this.sinkDescriptor);
    }
	
    @Override
	public void start(RuleContext ctx) {
        String methodMsg = "DfaSecurityRule::start";

        LOG.fine(methodMsg);
        if (sources.size() < 1) {
            sources = getDefaultSources();
        }
    }
	
	@Override
	public void apply(List<? extends Node>  list, RuleContext rulecontext) {
        String methodMsg = "DfaSecurityRule::apply";

        LOG.fine(methodMsg);
		
        if (sources.size() < 1) {
            sources = Utils.arrayAsHashSet(
                    getProperty(this.sourceDescriptor));
            LOG.warning(
                    "Unable to get sources from BaseSecurityRule. Defaulting to sources hard-coded in "
                            + this.getClass().getName()
                            + " or in the rule XML for " + this.getName() + ": "
                            + sources.toString());
        }
        this.sinks = Utils.arrayAsHashSet(getProperty(this.sinkDescriptor));
        super.apply(list, rulecontext);
    }

    private boolean isSource(String type, String variable) {
        String methodMsg = "DfaSecurityRule::isTaintedSource - {0}";

        LOG.log(Level.FINE, methodMsg, type + "." + variable);
		
        return sources.contains(type + "." + variable);

    }
	
    private boolean isTaintedVariable(String variable) {
        String methodMsg = "DfaSecurityRule::isTaintedVariable - {0}";

        LOG.log(Level.FINE, methodMsg, variable);

        return this.currentPathTaintedVariables.contains(variable);
    }
    @Override
    public Object visit(ASTConstructorDeclaration astConstructorDeclaration, Object data) {
        String methodMsg = "DfaSecurityRule::visit(ASTConstructorDeclaration) - {0}";
    	ASTClassOrInterfaceDeclaration astClass = astConstructorDeclaration.getFirstParentOfType(ASTClassOrInterfaceDeclaration.class);
        if (astClass == null) {
        	return data;
        }
        String visitedClass = astClass.getImage();
        String visitedMethod = visitedClass;
        this.rc = (RuleContext) data;
        LOG.log(Level.FINE, methodMsg,
                "ENTRY " + visitedClass + "." + visitedMethod);
        processReturnStatements(astConstructorDeclaration);
        processThrowsStatements(astConstructorDeclaration);
		
        runFinder(astConstructorDeclaration, visitedMethod);
        
        return data;
        
    }

    @Override
	public Object visit(ASTMethodDeclaration astMethodDeclaration, Object data) {
        String methodMsg = "DfaSecurityRule::visit(ASTMethodDeclaration) - {0}";

        ASTClassOrInterfaceDeclaration astClass = astMethodDeclaration.getFirstParentOfType(ASTClassOrInterfaceDeclaration.class);
        if (astClass == null) {
        	return data;
        }
        String visitedClass = astClass.getImage();
        String visitedMethod = astMethodDeclaration.getMethodName();
        

        LOG.log(Level.FINE, methodMsg,
                "ENTRY " + visitedClass + "." + visitedMethod);

        this.rc = (RuleContext) data;
               
        processReturnStatements(astMethodDeclaration);
        processThrowsStatements(astMethodDeclaration);

        runFinder(astMethodDeclaration, visitedMethod);



        LOG.log(Level.FINE, methodMsg, "Super.visit() " + visitedClass + "." + visitedMethod);

        super.visit(astMethodDeclaration, data);

        LOG.log(Level.FINE, methodMsg,  "EXIT " + visitedClass + "." + visitedMethod);
        
        return data;
    }

	private void runFinder(Node astMethodDeclaration, String visitedMethod) {
        DataFlowNode rootDataFlowNode = astMethodDeclaration.getDataFlowNode().getFlow().get(0);
		
        this.methodName = visitedMethod;
        this.methodDataFlowCount = 0;
        this.methodNumOfDataFlows = rootDataFlowNode.getFlow().size();
			
        DAAPathFinder daaPathFinder = new DAAPathFinder(rootDataFlowNode, this, MAX_DATAFLOWS);

        daaPathFinder.run();
		
	}

	private void processReturnStatements (Node node) {
    	processDataFlow(node, "./Block/BlockStatement/" + "/TryStatement/CatchStatement/"
                + "/ReturnStatement");
    }
    private void processThrowsStatements (Node node) {
    	processDataFlow(node,  "./Block/BlockStatement/" + "/TryStatement/CatchStatement/"
                + "/ThrowStatement");
    }
    private void processDataFlow(Node node, String xpath){
        try { 

			List<? extends Node> statements =  node.findChildNodesWithXPath(xpath);
        	if (statements != null && statements.size() > 0) {
                for (int i = 0; i < node.getDataFlowNode().getFlow().size(); i++) {
                	DataFlowNode current = node.getDataFlowNode().getFlow().get(i); 
                    for (int j = 0; j < statements.size(); j++) {                    	
                        if (current.equals(statements.get(j).getDataFlowNode())) {
                        	DataFlowNode next = node.getDataFlowNode().getFlow().get(i + 1);                       	
                        	if (!next.isType(NodeType.IF_EXPR)) {
                        		this.additionalDataFlowNodes.add(next);
                        	}                        	
                        } else {
                            LOG.log(Level.FINE, "methodMsg",
                                    "Unexpected condition when checking for ReturnStatement nodes");
                        }
                    }
                }
            }
        	
        }
        catch (JaxenException e) {
            LOG.log(Level.WARNING, "",
                    "Unexpected error when running Xpath query against AST - "
                    + e.getMessage());
        }
    }

    @Override
	public void execute(CurrentPath currentPath) {
        String methodMsg = "DfaSecurityRule::execute - {0}";

        this.methodDataFlowCount++;

        LOG.log(Level.FINE, methodMsg, "ENTRY");
        LOG.log(Level.FINE, methodMsg,
                "Dataflow count for current method: " + this.methodDataFlowCount);
        LOG.log(Level.FINE, methodMsg,
                "Path length for current dataflow: " + currentPath.getLength());

        if (this.methodDataFlowCount < MAX_DATAFLOWS) {
            for (Iterator<DataFlowNode> iterator = currentPath.iterator(); iterator.hasNext();) {
                DataFlowNode iDataFlowNode = iterator.next();
                Node node = iDataFlowNode.getNode();
                if (node instanceof ASTMethodDeclaration || node instanceof ASTConstructorDeclaration) {                	
                    this.currentPathTaintedVariables = new LinkedList<String>();
                    List<ASTFormalParameter> parameters = node.findDescendantsOfType(ASTFormalParameter.class);       
					for (ASTFormalParameter parameter : parameters) {
						ASTType type = parameter.getTypeNode();
						ASTVariableDeclaratorId name1 = parameter.getFirstDescendantOfType(ASTVariableDeclaratorId.class);						
						if (type.getType() != null && type.getType().getCanonicalName() != null && type.getType().getCanonicalName().startsWith("java.lang.String")){
							String name = name1.getImage();
							this.currentPathTaintedVariables.add(name);
						}
					}                   
                } else if (node instanceof ASTVariableDeclarator || node instanceof ASTStatementExpression) {
                    handleDataFlowNode(iDataFlowNode);
                } else {
                    LOG.log(Level.FINE, methodMsg, "Unhandled Node: " + iDataFlowNode.toString());
                } 
															
            }


            if (this.additionalDataFlowNodes.size() > 0) {
                DataFlowNode additionalRootNode = this.additionalDataFlowNodes.remove(0);                
                DAAPathFinder daaPathFinder = new DAAPathFinder(additionalRootNode, this, MAX_DATAFLOWS);
                this.methodDataFlowCount = 0;				
                daaPathFinder.run();
            }
			
        } else {
            LOG.log(Level.INFO, methodMsg,
                    "Maximum number of allowable dataflows " + MAX_DATAFLOWS
                    + " exceeded for " + this.methodName + " in "
                    + this.rc.getSourceCodeFilename()
                    + ". Total possible dataflows for method: "
                    + this.methodNumOfDataFlows);
        }

        LOG.log(Level.FINE, methodMsg, "EXIT");

    }

    private void handleDataFlowNode(DataFlowNode iDataFlowNode) {

        String methodMsg = "DfaSecurityRule::handleDataFlowNode - {0}";

        LOG.log(Level.FINE, methodMsg, "ENTRY");
        LOG.log(Level.FINE, methodMsg, iDataFlowNode.toString());
        LOG.log(Level.FINE, methodMsg, " # of variable access: "  + iDataFlowNode.getVariableAccess().size());

        boolean def = false;
        boolean ref = false;
        String variableName = "";
        

        for(VariableAccess access : iDataFlowNode.getVariableAccess()) {
        	if (access.isDefinition()){
        		def = true;
        		variableName = access.getVariableName();
        	}
        	if (access.isReference()) {
        		ref = true;
        	}
        }

        if (def) {
            handleVariableDefinition(iDataFlowNode, variableName);
        }

        if (ref && !def) {
            handleVariableReference(iDataFlowNode, variableName);
        }

        if (!def && !ref) {
            LOG.log(Level.FINE, methodMsg, "Unexpected Access Type");
        }

        LOG.log(Level.FINE, methodMsg, iDataFlowNode.toString());
        LOG.log(Level.FINE, methodMsg, "EXIT");
    }

    private void handleVariableReference(DataFlowNode iDataFlowNode,   String variableName) {

        String methodMsg = "DfaSecurityRule::handleVariableReference - {0}";

        LOG.log(Level.FINE, methodMsg, "ENTRY");
        Node simpleNode = iDataFlowNode.getNode();

        LOG.log(Level.FINEST, methodMsg, simpleNode.toString());

        if (isMethodCall(simpleNode)) {
			
            String type = "";
            String method = "";
			
            if (simpleNode.getFirstDescendantOfType(ASTAssignmentOperator.class) == null) {
                method = getMethod(simpleNode.getFirstDescendantOfType(ASTPrimaryExpression.class));
                type = Utils.getType(simpleNode.getFirstDescendantOfType(ASTPrimaryExpression.class), this.rc, method);
            } else {
				
                method = getMethod(
                        simpleNode.getFirstDescendantOfType(ASTExpression.class));
                type = Utils.getType(
                        simpleNode.getFirstDescendantOfType(ASTExpression.class), this.rc,
                        method);
            }

            LOG.log(Level.FINE, methodMsg, "type " + type + " invoking method " + method);

            if (isSink(type, method)) {
                LOG.finest("Checking method " + method + " for tainted arguments");
                analyzeMethodArgs(simpleNode);
            }
			
        } else {
            LOG.log(Level.FINE, methodMsg,  "Do we need to do any further processing here?");
			
        }

        LOG.log(Level.FINE, methodMsg, "EXIT");

    }

    private void analyzeMethodArgs(Node simpleNode) {

        ASTArgumentList argListNode = simpleNode.getFirstDescendantOfType(ASTArgumentList.class);
        List<ASTName> listOfArgs = new ArrayList<ASTName>();

        listOfArgs.addAll(argListNode.findDescendantsOfType(ASTName.class));

        for (Iterator<ASTName> iterator = listOfArgs.iterator(); iterator.hasNext();) {			
            ASTName name = iterator.next();
			String argumentName = name.getImage();
            String argumentType = "";
            if (argumentName.indexOf('.') != -1) {
                argumentName = argumentName.substring(argumentName.indexOf('.') + 1);
            }

            argumentType = Utils.getType(name, this.rc, argumentName);
            if (isSource(argumentType, argumentName) || isTaintedVariable(argumentName)) {
                addSecurityViolation(this, this.rc, simpleNode, getMessage(), argumentName, argumentType);
            }
        }
		
    }

    private boolean isSink(String objectType, String objectMethod) {
        String methodMsg = "DfaSecurityRule::isSink - {0}";
        LOG.log(Level.FINE, methodMsg, objectType + "." + objectMethod);		
        return this.sinks.contains(objectType + "." + objectMethod);
    }

    private boolean isMethodCall(Node node) {

        String methodMsg = "DfaSecurityRule::isMethodCall";

        LOG.log(Level.FINE, methodMsg);

        // FIXME ??
        ASTArguments arguments = node.getFirstDescendantOfType(ASTArguments.class);

        return (arguments != null);
    }

    private void handleVariableDefinition(DataFlowNode iDataFlowNode, String variable) {

        String methodMsg = "DfaSecurityRule::handleVariableDefinition - {0}";

        LOG.log(Level.FINE, methodMsg, "ENTRY");
        Node simpleNode = iDataFlowNode.getNode();

        LOG.log(Level.FINEST, methodMsg, simpleNode.toString());

        if (simpleNode.hasDescendantOfType(ASTConditionalExpression.class)) {
            handleConditionalExpression(simpleNode, variable);
        } else if (simpleNode.hasDescendantOfType(ASTExpression.class)) {
			List<ASTPrimaryExpression> primaryExpressions = simpleNode.findDescendantsOfType(ASTPrimaryExpression.class);        	
        	for (ASTPrimaryExpression p: primaryExpressions) {
        		if (p.hasDescendantOfType(ASTName.class)) {
        			analyzeNode(p, variable);
        		}
        	} 
        } else {
            LOG.log(Level.FINE, methodMsg, "Unhandled node: " + simpleNode.toString());
        }
        LOG.log(Level.FINE, methodMsg, "EXIT");

    }

    private void handleConditionalExpression(Node node, String variable) {

        Node ifResult = node.getFirstDescendantOfType(ASTConditionalExpression.class).jjtGetChild(1);

        analyzeNode(ifResult, variable);
        Node elseResult = node.getFirstDescendantOfType(ASTConditionalExpression.class).jjtGetChild(2);

        if (elseResult instanceof ASTAdditiveExpression) {
            List<ASTPrimaryExpression> primaryExpressions = elseResult.findChildrenOfType(
                    ASTPrimaryExpression.class);

            for (Iterator<ASTPrimaryExpression> iterator = primaryExpressions.iterator(); iterator.hasNext();) {
                analyzeNode(iterator.next(), variable);
            }
        } else if (elseResult instanceof ASTPrimaryExpression) {
            analyzeNode(elseResult, variable);
        }

    }

    private void analyzeNode(Node node, String variable) {

        String methodMsg = "DfaSecurityRule::checkNodeForTaint - {0}";

        LOG.log(Level.FINE, methodMsg, "ENTRY");

        if (isMethodCall(node)) {
            String method = getMethod(node);
            String type = Utils.getType(node, this.rc, method);

            LOG.log(Level.FINE, methodMsg,
                    "Variable " + variable + " initialized with Type: " + type
                    + " Method: " + method);

            if (isSource(type, method)) {
            	LOG.log(Level.FINE, methodMsg, "Adding " + variable + " to list of taint");
                this.currentPathTaintedVariables.add(variable);
            } else if (isSink(type, method)) {
                analyzeMethodArgs(node);
            } else if (isPassThrough(type, method)) {
            	//
            }
        } else {
            LOG.log(Level.FINE, methodMsg, "Initialized with variable or literal");			
            List<ASTName> astNames = node.findDescendantsOfType(ASTName.class);
            if (astNames.size() > 0) {
                analyzeVariable(variable, astNames);
            }
        }
        LOG.log(Level.FINE, methodMsg, "EXIT");
    }

    private String getMethod(Node node) {

        String method = "";
        
        if (node.hasDescendantOfType (ASTClassOrInterfaceType.class)) {
            method = node.getFirstDescendantOfType(ASTClassOrInterfaceType.class).getImage();
        } else {
        	ASTName astName = node.getFirstDescendantOfType(ASTName.class);
        	if (astName != null) {
        		method = astName.getImage();
        	}
        	else {
        		method ="";
        	}
        }

        if (method.indexOf('.') != -1) {
            method = method.substring(method.indexOf('.') + 1);
        }

        return method;
    }


	private boolean isPassThrough(String type, String method) {

        String methodMsg = "DfaSecurityRule::isPassthroughMethod - {0}";

        LOG.log(Level.FINE, methodMsg, "Not Implemented");

        return false;
    }

    private void analyzeVariable(String variableName,
            List<ASTName> listOfAstNames) {
        String methodMsg = "DfaSecurityRule::checkVariableForTaint - {0}";

        LOG.log(Level.FINE, methodMsg, "ENTRY");

        if (listOfAstNames.size() > 0) {
            for (int i = 0; i < listOfAstNames.size(); i++) {
                ASTName name = listOfAstNames.get(i);
                String var = name.getImage();
                String type = Utils.getType(name, this.rc, var);

                if (var.indexOf('.') != -1) {
                    var = var.substring(var.indexOf('.') + 1);
                }

                LOG.log(Level.FINE, methodMsg,
                        "Variable " + variableName + " initialized with " + var
                        + " of type " + type);
				
                if (isSource(type, var) || isTaintedVariable(var)) {
                    LOG.log(Level.FINE, methodMsg,
                            "Adding " + variableName + " to list of taint");
                    this.currentPathTaintedVariables.add(variableName);
                }
            }

        }

        LOG.log(Level.FINE, methodMsg, "EXIT");
    }

}
