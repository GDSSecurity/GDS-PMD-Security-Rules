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
import net.sourceforge.pmd.ast.ASTAdditiveExpression;
import net.sourceforge.pmd.ast.ASTArgumentList;
import net.sourceforge.pmd.ast.ASTArguments;
import net.sourceforge.pmd.ast.ASTAssignmentOperator;
import net.sourceforge.pmd.ast.ASTClassOrInterfaceDeclaration;
import net.sourceforge.pmd.ast.ASTClassOrInterfaceType;
import net.sourceforge.pmd.ast.ASTConditionalExpression;
import net.sourceforge.pmd.ast.ASTExpression;
import net.sourceforge.pmd.ast.ASTMethodDeclaration;
import net.sourceforge.pmd.ast.ASTName;
import net.sourceforge.pmd.ast.ASTPrimaryExpression;
import net.sourceforge.pmd.ast.ASTReturnStatement;
import net.sourceforge.pmd.ast.ASTStatementExpression;
import net.sourceforge.pmd.ast.ASTThrowStatement;
import net.sourceforge.pmd.ast.ASTVariableDeclarator;
import net.sourceforge.pmd.ast.SimpleNode;
import net.sourceforge.pmd.dfa.IDataFlowNode;
import net.sourceforge.pmd.dfa.pathfinder.CurrentPath;
import net.sourceforge.pmd.dfa.pathfinder.DAAPathFinder;
import net.sourceforge.pmd.dfa.pathfinder.Executable;
import net.sourceforge.pmd.dfa.variableaccess.VariableAccess;
import net.sourceforge.pmd.properties.StringProperty;

import org.jaxen.JaxenException;

import com.gdssecurity.pmd.Utils;
import com.gdssecurity.pmd.rules.BaseSecurityRule;


public class DfaSecurityRule extends BaseSecurityRule
        implements Executable {
    private static final Logger LOG = getLogger();
	
    private LinkedList<String> currentPathTaintedVariables;
	
    private static HashSet<String> sources = new HashSet<String>();
	
    private PropertyDescriptor sourceDescriptor = new StringProperty("sources",
            "",
            new String[] {
        "javax.servlet.http.HttpServletRequest.getParameter" }, 1.0f, '|');

    private HashSet<String> sinks;

    private PropertyDescriptor sinkDescriptor = new StringProperty("sinks", "",
            new String[] { "" }, 1.0f, '|');

    private RuleContext rc;
    private int methodDataFlowCount;
    private String methodName = "";
    private int methodNumOfDataFlows;
	
    private List<IDataFlowNode> additionalDataFlowNodes = new ArrayList<IDataFlowNode>();
	
    private static final int MAX_DATAFLOWS = 10;
	
    public void start(RuleContext ctx) {
        String methodMsg = "DfaSecurityRule::start";

        LOG.fine(methodMsg);
        if (sources.size() < 1) {
            sources = getDefaultSources();
        }
    }
	
    public void apply(List list, RuleContext rulecontext) {
        String methodMsg = "DfaSecurityRule::apply";

        LOG.fine(methodMsg);
		
        if (sources.size() < 1) {
            sources = Utils.arrayAsHashSet(
                    getStringProperties(this.sourceDescriptor));
            LOG.warning(
                    "Unable to get sources from BaseSecurityRule. Defaulting to sources hard-coded in "
                            + this.getClass().getName()
                            + " or in the rule XML for " + this.getName() + ": "
                            + sources.toString());
        }
        sinks = Utils.arrayAsHashSet(getStringProperties(sinkDescriptor));
        super.apply(list, rulecontext);
    }

    private boolean isSource(String type, String variable) {
        String methodMsg = "DfaSecurityRule::isTaintedSource - {0}";

        LOG.log(Level.FINE, methodMsg, type + "." + variable);
		
        return sources.contains(type + "." + variable) ? true : false;

    }
	
    private boolean isTaintedVariable(String variable) {
        String methodMsg = "DfaSecurityRule::isTaintedVariable - {0}";

        LOG.log(Level.FINE, methodMsg, variable);

        return currentPathTaintedVariables.contains(variable) ? true : false;
    }

    public Object visit(ASTMethodDeclaration astMethodDeclaration, Object data) {
        String methodMsg = "DfaSecurityRule::visit(ASTMethodDeclaration) - {0}";

        String visitedClass = astMethodDeclaration.getFirstParentOfType(ASTClassOrInterfaceDeclaration.class).getImage();
        String visitedMethod = astMethodDeclaration.getMethodName();

        LOG.log(Level.FINE, methodMsg,
                "ENTRY " + visitedClass + "." + visitedMethod);

        rc = (RuleContext) data;
		
        try { 
				
            List<ASTReturnStatement> returnStatements = astMethodDeclaration.findChildNodesWithXPath(
                    "./Block/BlockStatement/" + "/TryStatement/CatchStatement/"
                    + "/ReturnStatement");

            if (returnStatements != null && returnStatements.size() > 0) {
                for (int i = 0; i
                        < astMethodDeclaration.getDataFlowNode().getFlow().size(); i++) {
					
                    for (int j = 0; j < returnStatements.size(); j++) {
                        if (((IDataFlowNode) astMethodDeclaration.getDataFlowNode().getFlow().get(i)).equals(
                                returnStatements.get(j).getDataFlowNode())) {
                            additionalDataFlowNodes.add(
                                    astMethodDeclaration.getDataFlowNode().getFlow().get(
                                            i + 1));
                        } else {
                            LOG.log(Level.FINE, methodMsg,
                                    "Unexpected condition when checking for ReturnStatement nodes");
                        }
                    }
                }
            }

            List<ASTThrowStatement> throwStatements = astMethodDeclaration.findChildNodesWithXPath(
                    "./Block/BlockStatement/" + "/TryStatement/CatchStatement/"
                    + "/ThrowStatement");

            if (throwStatements != null && throwStatements.size() > 0) {
                for (int i = 0; i
                        < astMethodDeclaration.getDataFlowNode().getFlow().size(); i++) {
					
                    for (int j = 0; j < throwStatements.size(); j++) {
                        if (((IDataFlowNode) astMethodDeclaration.getDataFlowNode().getFlow().get(i)).equals(
                                throwStatements.get(j).getDataFlowNode())) {
                            additionalDataFlowNodes.add(
                                    astMethodDeclaration.getDataFlowNode().getFlow().get(
                                            i + 1));
                        } else {
                            LOG.log(Level.FINE, methodMsg,
                                    "Unexpected condition when checking for ThrowStatement nodes");
                        }
                    }
                }
            }
        } catch (JaxenException e) {
            LOG.log(Level.WARNING, methodMsg,
                    "Unexpected error when running Xpath query against AST - "
                    + e.getMessage());
        }

        IDataFlowNode rootDataFlowNode = (IDataFlowNode) astMethodDeclaration.getDataFlowNode().getFlow().get(
                0);
		
        methodName = visitedMethod;
        methodDataFlowCount = 0;
        methodNumOfDataFlows = rootDataFlowNode.getFlow().size();
			
        DAAPathFinder daaPathFinder = new DAAPathFinder(rootDataFlowNode, this,
                MAX_DATAFLOWS);

        daaPathFinder.run();

        LOG.log(Level.FINE, methodMsg,
                "Super.visit() " + visitedClass + "." + visitedMethod);

        super.visit(astMethodDeclaration, data);

        LOG.log(Level.FINE, methodMsg,
                "EXIT " + visitedClass + "." + visitedMethod);

        return data;
    }

    public void execute(CurrentPath currentPath) {
        String methodMsg = "DfaSecurityRule::execute - {0}";

        methodDataFlowCount++;

        LOG.log(Level.FINE, methodMsg, "ENTRY");
        LOG.log(Level.FINE, methodMsg,
                "Dataflow count for current method: " + methodDataFlowCount);
        LOG.log(Level.FINE, methodMsg,
                "Path length for current dataflow: " + currentPath.getLength());

        if (methodDataFlowCount < MAX_DATAFLOWS) {
            for (Iterator<IDataFlowNode> iterator = currentPath.iterator(); iterator.hasNext();) {
                IDataFlowNode iDataFlowNode = iterator.next();

                if (iDataFlowNode.getSimpleNode() instanceof ASTMethodDeclaration) {
                    currentPathTaintedVariables = new LinkedList<String>();
                } else if (iDataFlowNode.getSimpleNode() instanceof ASTVariableDeclarator
                        || iDataFlowNode.getSimpleNode() instanceof ASTStatementExpression) {
                    handleDataFlowNode(iDataFlowNode);
                } else {
                    LOG.log(Level.FINE, methodMsg,
                            "Unhandled Node: " + iDataFlowNode.toString());
                } 
															
            }

            if (additionalDataFlowNodes.size() > 0) {
                IDataFlowNode additionalRootNode = additionalDataFlowNodes.get(0);

                additionalDataFlowNodes.remove(0);
                DAAPathFinder daaPathFinder = new DAAPathFinder(
                        additionalRootNode, this, MAX_DATAFLOWS);
				
                methodDataFlowCount = 0;
				
                daaPathFinder.run();
            }
			
        } else {
            LOG.log(Level.INFO, methodMsg,
                    "Maximum number of allowable dataflows " + MAX_DATAFLOWS
                    + " exceeded for " + methodName + " in "
                    + rc.getSourceCodeFilename()
                    + ". Total possible dataflows for method: "
                    + methodNumOfDataFlows);
        }

        LOG.log(Level.FINE, methodMsg, "EXIT");

    }

    private void handleDataFlowNode(IDataFlowNode iDataFlowNode) {

        String methodMsg = "DfaSecurityRule::handleDataFlowNode - {0}";

        LOG.log(Level.FINE, methodMsg, "ENTRY");
        LOG.log(Level.FINE, methodMsg, iDataFlowNode.toString());
        LOG.log(Level.FINE, methodMsg,
                " # of variable access: "
                + iDataFlowNode.getVariableAccess().size());

        boolean def = false;
        boolean ref = false;
        String variableName = "";

        for (int i = 0; i < iDataFlowNode.getVariableAccess().size(); i++) {
            if (((VariableAccess) iDataFlowNode.getVariableAccess().get(i)).isDefinition()) {
                def = true;
                variableName = ((VariableAccess) iDataFlowNode.getVariableAccess().get(i)).getVariableName();
            }
            if (((VariableAccess) iDataFlowNode.getVariableAccess().get(i)).isReference()) {
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

    private void handleVariableReference(IDataFlowNode iDataFlowNode,
            String variableName) {

        String methodMsg = "DfaSecurityRule::handleVariableReference - {0}";

        LOG.log(Level.FINE, methodMsg, "ENTRY");
        SimpleNode simpleNode = iDataFlowNode.getSimpleNode();

        LOG.log(Level.FINEST, methodMsg, simpleNode.toString());

        if (isMethodCall(simpleNode)) {
			
            String type = "";
            String method = "";
			
            if (simpleNode.getFirstChildOfType(ASTAssignmentOperator.class)
                    == null) {
                method = getMethod(
                        simpleNode.getFirstChildOfType(
                                ASTPrimaryExpression.class));
                type = Utils.getType(
                        simpleNode.getFirstChildOfType(
                                ASTPrimaryExpression.class),
                                rc,
                                method);
            } else {
				
                method = getMethod(
                        simpleNode.getFirstChildOfType(ASTExpression.class));
                type = Utils.getType(
                        simpleNode.getFirstChildOfType(ASTExpression.class), rc,
                        method);
            }

            LOG.log(Level.FINE, methodMsg,
                    "type " + type + " invoking method " + method);

            if (isSink(type, method)) {
                LOG.finest(
                        "Checking method " + method + " for tainted arguments");
                analyzeMethodArgs(simpleNode);
            }
			
        } else {
            LOG.log(Level.FINE, methodMsg,
                    "Do we need to do any further processing here?");
			
        }

        LOG.log(Level.FINE, methodMsg, "EXIT");

    }

    private void analyzeMethodArgs(SimpleNode simpleNode) {

        ASTArgumentList argListNode = simpleNode.getFirstChildOfType(
                ASTArgumentList.class);
        List<ASTName> listOfArgs = new ArrayList<ASTName>();

        listOfArgs.addAll(argListNode.findChildrenOfType(ASTName.class));

        for (Iterator<ASTName> iterator = listOfArgs.iterator(); iterator.hasNext();) {
			
            ASTName name = iterator.next();
			
            String argumentName = name.getImage();
            String argumentType = "";

            if (argumentName.indexOf('.') != -1) {
                argumentName = argumentName.substring(
                        argumentName.indexOf('.') + 1);
            }

            argumentType = Utils.getType(name, rc, argumentName);

            if (isSource(argumentType, argumentName)
                    || isTaintedVariable(argumentName)) {
                addSecurityViolation(this, rc, simpleNode, getMessage(),
                        argumentName, argumentType);
            }
        }
		
    }

    private boolean isSink(String objectType, String objectMethod) {

        String methodMsg = "DfaSecurityRule::isSink - {0}";

        LOG.log(Level.FINE, methodMsg, objectType + "." + objectMethod);
		
        return sinks.contains(objectType + "." + objectMethod) ? true : false;
    }

    private boolean isMethodCall(SimpleNode node) {

        String methodMsg = "DfaSecurityRule::isMethodCall";

        LOG.log(Level.FINE, methodMsg);

        ASTArguments arguments = node.getFirstChildOfType(ASTArguments.class);

        return (arguments != null) ? true : false;
    }

    private void handleVariableDefinition(IDataFlowNode iDataFlowNode,
            String variable) {

        String methodMsg = "DfaSecurityRule::handleVariableDefinition - {0}";

        LOG.log(Level.FINE, methodMsg, "ENTRY");
        SimpleNode simpleNode = iDataFlowNode.getSimpleNode();

        LOG.log(Level.FINEST, methodMsg, simpleNode.toString());

        if (simpleNode.containsChildOfType(ASTConditionalExpression.class)) {
            handleConditionalExpression(simpleNode, variable);
        } else if (simpleNode.containsChildOfType(ASTExpression.class)) {
			
            List<ASTPrimaryExpression> primaryExpressions = simpleNode.getFirstChildOfType(ASTExpression.class).findChildrenOfType(
                    ASTPrimaryExpression.class);

            for (int i = 0; i < primaryExpressions.size(); i++) {
                if (primaryExpressions.get(i).getFirstChildOfType(ASTName.class)
                        != null) {
                    analyzeNode(primaryExpressions.get(i), variable);
                }
            }
        } else {
            LOG.log(Level.FINE, methodMsg,
                    "Unhandled node: " + simpleNode.toString());
        }

        LOG.log(Level.FINE, methodMsg, "EXIT");

    }

    private void handleConditionalExpression(SimpleNode node, String variable) {

        SimpleNode ifResult = (ASTExpression) node.getFirstChildOfType(ASTConditionalExpression.class).jjtGetChild(
                1);

        analyzeNode(ifResult, variable);
        SimpleNode elseResult = (SimpleNode) node.getFirstChildOfType(ASTConditionalExpression.class).jjtGetChild(
                2);

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

    private void analyzeNode(SimpleNode node, String variable) {

        String methodMsg = "DfaSecurityRule::checkNodeForTaint - {0}";

        LOG.log(Level.FINE, methodMsg, "ENTRY");

        if (isMethodCall(node)) {
            String method = getMethod(node);
            String type = Utils.getType(node, rc, method);

            LOG.log(Level.FINE, methodMsg,
                    "Variable " + variable + " initialized with Type: " + type
                    + " Method: " + method);

            if (isSource(type, method)) {
				
                LOG.log(Level.FINE, methodMsg,
                        "Adding " + variable + " to list of taint");
                currentPathTaintedVariables.add(variable);
            } else if (isSink(type, method)) {
                analyzeMethodArgs(node);
            } else if (isPassThrough(type, method)) {}
        } else {
            LOG.log(Level.FINE, methodMsg,
                    "Initialized with variable or literal");
			
            List<ASTName> astNames = node.findChildrenOfType(ASTName.class);

            if (astNames.size() > 0) {
                analyzeVariable(variable, astNames);
            }
        }

        LOG.log(Level.FINE, methodMsg, "EXIT");
    }

    private String getMethod(SimpleNode node) {

        String method = "";

        if (node.containsChildOfType(ASTClassOrInterfaceType.class)) {
            method = node.getFirstChildOfType(ASTClassOrInterfaceType.class).getImage();
        } else {
            method = node.getFirstChildOfType(ASTName.class).getImage();
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
                String type = Utils.getType(name, rc, var);

                if (var.indexOf('.') != -1) {
                    var = var.substring(var.indexOf('.') + 1);
                }

                LOG.log(Level.FINE, methodMsg,
                        "Variable " + variableName + " initialized with " + var
                        + " of type " + type);
				
                if (isSource(type, var) || isTaintedVariable(var)) {
                    LOG.log(Level.FINE, methodMsg,
                            "Adding " + variableName + " to list of taint");
                    currentPathTaintedVariables.add(variableName);
                }
            }

        }

        LOG.log(Level.FINE, methodMsg, "EXIT");
    }

}
