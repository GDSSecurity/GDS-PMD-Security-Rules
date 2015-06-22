/*
 * This code is licensed under the Reciprocal Public License 1.5 (RPL1.5)http://www.opensource.org/licenses/rpl1.5
 * 
 * Copyright (c) 2012 Gotham Digital Science, LLC -- All Rights Reserved
 *
 */


package com.gdssecurity.pmd.rules.dfa;


import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
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
import net.sourceforge.pmd.lang.java.ast.ASTFieldDeclaration;
import net.sourceforge.pmd.lang.java.ast.ASTFormalParameter;
import net.sourceforge.pmd.lang.java.ast.ASTMethodDeclaration;
import net.sourceforge.pmd.lang.java.ast.ASTName;
import net.sourceforge.pmd.lang.java.ast.ASTPrimaryExpression;
import net.sourceforge.pmd.lang.java.ast.ASTPrimaryPrefix;
import net.sourceforge.pmd.lang.java.ast.ASTPrimarySuffix;
import net.sourceforge.pmd.lang.java.ast.ASTStatementExpression;
import net.sourceforge.pmd.lang.java.ast.ASTType;
import net.sourceforge.pmd.lang.java.ast.ASTTypeDeclaration;
import net.sourceforge.pmd.lang.java.ast.ASTVariableDeclarator;
import net.sourceforge.pmd.lang.java.ast.ASTVariableDeclaratorId;
import net.sourceforge.pmd.lang.rule.properties.StringMultiProperty;

import org.jaxen.JaxenException;

import com.gdssecurity.pmd.Utils;
import com.gdssecurity.pmd.rules.BaseSecurityRule;


public class DfaSecurityRule extends BaseSecurityRule  implements Executable {
    private static final Logger LOG = getLogger();
	
    private Set<String> currentPathTaintedVariables;
    
    private Map<String, Class<?>> fieldTypes;
    private Map<String, Class<?>> functionParameterTypes;
	
    private PropertyDescriptor<String[]> sourceDescriptor = new StringMultiProperty("sources",
            "TODO",
            new String[] {
        "javax.servlet.http.HttpServletRequest.getParameter" }, 1.0f, '|');
    private HashSet<String> sinks;

    private PropertyDescriptor<String[]> sinkDescriptor = new StringMultiProperty("sinks", "TODO",
            new String[] { "" }, 1.0f, '|');

    private RuleContext rc;
    private int methodDataFlowCount;
	
    private List<DataFlowNode> additionalDataFlowNodes = new ArrayList<DataFlowNode>();
	
    private static final int MAX_DATAFLOWS = 1000;
    
    public DfaSecurityRule () {
    	super();
    	this.propertyDescriptors.add(this.sourceDescriptor);
    	this.propertyDescriptors.add(this.sinkDescriptor);
    }
	
    @Override
	public void start(RuleContext ctx) {
        if (sources.isEmpty()) {
            sources = getDefaultSources();
        }
    }
	
	@Override
	public void apply(List<? extends Node>  list, RuleContext rulecontext) {		
        if (sources.isEmpty()) {
            sources = Utils.arrayAsHashSet(getProperty(this.sourceDescriptor));
        }
        this.sinks = Utils.arrayAsHashSet(getProperty(this.sinkDescriptor));
        super.apply(list, rulecontext);
    }

    private boolean isSource(String type, String variable) {
        return sources.contains(type + "." + variable);
    }
	
    private boolean isTaintedVariable(String variable) {
        return this.currentPathTaintedVariables.contains(variable);
    }
    @Override
    public Object visit(ASTConstructorDeclaration astConstructorDeclaration, Object data) {
    	ASTClassOrInterfaceDeclaration astClass = astConstructorDeclaration.getFirstParentOfType(ASTClassOrInterfaceDeclaration.class);
        if (astClass == null) {
        	return data;
        }
        String visitedClass = astClass.getImage();
        String visitedMethod = visitedClass;
        this.rc = (RuleContext) data;
        processReturnStatements(astConstructorDeclaration);
        processThrowsStatements(astConstructorDeclaration);
        runFinder(astConstructorDeclaration, visitedMethod);
        return data;
        
    }

    @Override
	public Object visit(ASTMethodDeclaration astMethodDeclaration, Object data) {

        ASTClassOrInterfaceDeclaration astClass = astMethodDeclaration.getFirstParentOfType(ASTClassOrInterfaceDeclaration.class);
        if (astClass == null) {
        	return data;
        }
        String visitedMethod = astMethodDeclaration.getMethodName();
        
        this.rc = (RuleContext) data;
               
        processReturnStatements(astMethodDeclaration);
        processThrowsStatements(astMethodDeclaration);

        runFinder(astMethodDeclaration, visitedMethod);

        super.visit(astMethodDeclaration, data);
        
        return data;
    }

	private void runFinder(Node astMethodDeclaration, String visitedMethod) {
        DataFlowNode rootDataFlowNode = astMethodDeclaration.getDataFlowNode().getFlow().get(0);
		
        this.methodDataFlowCount = 0;
			
        DAAPathFinder daaPathFinder = new DAAPathFinder(rootDataFlowNode, this, MAX_DATAFLOWS);

        daaPathFinder.run();
		
	}

	private void processReturnStatements (Node node) {
    	processDataFlow(node, "./Block/BlockStatement//TryStatement/CatchStatement//ReturnStatement");
    }
    private void processThrowsStatements (Node node) {
    	processDataFlow(node,  "./Block/BlockStatement//TryStatement/CatchStatement//ThrowStatement");
    }
    private void processDataFlow(Node node, String xpath){
        try { 

			List<? extends Node> statements =  node.findChildNodesWithXPath(xpath);
			if (statements == null || statements.isEmpty()) {
				return;
			}
			int i = 0;
			for (DataFlowNode current: node.getDataFlowNode().getFlow()) {
				for (Node statement: statements) {
					if (current.equals(statement.getDataFlowNode())) {
						DataFlowNode next = node.getDataFlowNode().getFlow().get(i + 1);
						if (!next.isType(NodeType.IF_EXPR)) {
							this.additionalDataFlowNodes.add(next);
						}
					}
				}
				i++;
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

        this.methodDataFlowCount++;


        if (this.methodDataFlowCount < MAX_DATAFLOWS) {
            for (Iterator<DataFlowNode> iterator = currentPath.iterator(); iterator.hasNext();) {
                DataFlowNode iDataFlowNode = iterator.next();
                Node node = iDataFlowNode.getNode();
                if (node instanceof ASTMethodDeclaration || node instanceof ASTConstructorDeclaration) {                	
                    this.currentPathTaintedVariables = new HashSet<String>();                    
                    addMethodParamsToTaintedVariables(node);
                    addClassFieldsToTaintedVariables(node);
                } else if (node instanceof ASTVariableDeclarator || node instanceof ASTStatementExpression) {
                    handleDataFlowNode(iDataFlowNode);
                } 										
            }


			if (!this.additionalDataFlowNodes.isEmpty()) {
				DataFlowNode additionalRootNode = this.additionalDataFlowNodes.remove(0);
				DAAPathFinder daaPathFinder = new DAAPathFinder(additionalRootNode, this, MAX_DATAFLOWS);
				this.methodDataFlowCount = 0;
				daaPathFinder.run();
			}
			
        } 
    }



	private void addClassFieldsToTaintedVariables(Node node) {
		this.fieldTypes = new HashMap<String, Class<?>>();     
		ASTTypeDeclaration classDeclaration = node.getFirstParentOfType(ASTTypeDeclaration.class);
		if (classDeclaration == null) {
			return;
		}
		List<ASTFieldDeclaration> fields = classDeclaration.findDescendantsOfType(ASTFieldDeclaration.class);
		for (ASTFieldDeclaration field : fields) {			
				Class<?> type = field.getType();
				ASTVariableDeclarator declarator = field.getFirstChildOfType(ASTVariableDeclarator.class);
				ASTVariableDeclaratorId name1 = declarator.getFirstChildOfType(ASTVariableDeclaratorId.class);
				if (name1 != null) {
					String name = name1.getImage();
					fieldTypes.put(name, type);
					if (isTypeStringOrStringBuffer(field.getType())) {
						currentPathTaintedVariables.add("this." + name);
					}
				}
			
		}
		
	}

	private void addMethodParamsToTaintedVariables(Node node) {
		this.functionParameterTypes = new HashMap<String, Class<?>>();
		List<ASTFormalParameter> parameters = node.findDescendantsOfType(ASTFormalParameter.class);       
		for (ASTFormalParameter parameter : parameters) {
			ASTType type = parameter.getTypeNode();
			ASTVariableDeclaratorId name1 = parameter.getFirstDescendantOfType(ASTVariableDeclaratorId.class);						
			String name = name1.getImage();
			if (name != null && type != null) {
				functionParameterTypes.put(name, type.getType());
			}
			if (name != null && isTypeStringOrStringBuffer(type)){
				this.currentPathTaintedVariables.add(name);
			}
		}
	}

	private boolean isTypeStringOrStringBuffer(Class<?> clazz) {
		if (clazz == null) {
			return false;
		}
		return clazz.isAssignableFrom(String.class) || clazz.isAssignableFrom(StringBuffer.class) || clazz.isAssignableFrom(StringBuilder.class);
	}
	
    private boolean isTypeStringOrStringBuffer(ASTType type) {
    	if (type == null) {
    		return false;
    	}
    	return isTypeStringOrStringBuffer(type.getType());
	}

	private void handleDataFlowNode(DataFlowNode iDataFlowNode) {
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


    }

    private void handleVariableReference(DataFlowNode iDataFlowNode,   String variableName) {


        Node simpleNode = iDataFlowNode.getNode();


        if (isMethodCall(simpleNode)) {
			
            String type = "";
            String method = "";
			
            Node astMethod = null;
            if (simpleNode.getFirstDescendantOfType(ASTAssignmentOperator.class) == null) {
            	astMethod = simpleNode.getFirstDescendantOfType(ASTPrimaryExpression.class);
            }
            else {
            	astMethod = simpleNode.getFirstDescendantOfType(ASTExpression.class);
            }
            method = getMethod(astMethod);
            type = getType(astMethod, method);    
           


            if (isSink(type, method)) {
                analyzeMethodArgs(simpleNode);
            }
			
        } 
    }

    private void analyzeMethodArgs(Node simpleNode) {

        ASTArgumentList argListNode = simpleNode.getFirstDescendantOfType(ASTArgumentList.class);
        List<ASTName> listOfArgs = new ArrayList<ASTName>();

        listOfArgs.addAll(argListNode.findDescendantsOfType(ASTName.class));

        for (ASTName name: listOfArgs) {
			String argumentName = name.getImage();
            if (argumentName.indexOf('.') != -1) {
                argumentName = argumentName.substring(argumentName.indexOf('.') + 1);
            }
            if (isTaintedVariable(argumentName) || isSource(getType(name, argumentName), argumentName)) {
                addSecurityViolation(this, this.rc, simpleNode, getMessage(), argumentName);
            }
        }
		
    }

    private boolean isSink(String objectType, String objectMethod) {
        return this.sinks.contains(objectType + "." + objectMethod);
    }

    private boolean isMethodCall(Node node) {
        ASTArguments arguments = node.getFirstDescendantOfType(ASTArguments.class);
        return arguments != null;
    }

    private void handleVariableDefinition(DataFlowNode iDataFlowNode, String variable) {
        Node simpleNode = iDataFlowNode.getNode();

        if (simpleNode.hasDescendantOfType(ASTConditionalExpression.class)) {
            handleConditionalExpression(simpleNode, variable);
        } else if (simpleNode.hasDescendantOfType(ASTExpression.class)) {
			List<ASTPrimaryExpression> primaryExpressions = simpleNode.findDescendantsOfType(ASTPrimaryExpression.class);        	
        	for (ASTPrimaryExpression p: primaryExpressions) {
       			analyzeNode(p, variable);        		
        	} 
        } 

    }

    private void handleConditionalExpression(Node node, String variable) {

    	Node wholeIf = node.getFirstDescendantOfType(ASTConditionalExpression.class);
        Node ifResult = wholeIf.jjtGetChild(1);

        analyzeNode(ifResult, variable);
        Node elseResult = wholeIf.jjtGetChild(2);

        if (elseResult instanceof ASTAdditiveExpression) {
            List<ASTPrimaryExpression> primaryExpressions = elseResult.findChildrenOfType(ASTPrimaryExpression.class);

            for (ASTPrimaryExpression primaryExpression: primaryExpressions) { 
                analyzeNode(primaryExpression, variable);
            }
        } else if (elseResult instanceof ASTPrimaryExpression) {
            analyzeNode(elseResult, variable);
        }

    }

    private void analyzeNode(Node node, String variable) {
        if (isMethodCall(node)) {
            String method = getMethod(node);
            String type = getType(node, method);

            if (isSource(type, method)) {
                this.currentPathTaintedVariables.add(variable);
            } else if (isSink(type, method)) {
                analyzeMethodArgs(node);
            } 
        } else if (node.hasDescendantOfType(ASTName.class)){
            List<ASTName> astNames = node.findDescendantsOfType(ASTName.class);
            analyzeVariable(variable, astNames);            
        }
        else {
        	ASTPrimaryPrefix prefix = node.getFirstChildOfType(ASTPrimaryPrefix.class);
        	ASTPrimarySuffix suffix = node.getFirstChildOfType(ASTPrimarySuffix.class);
        	if ((prefix == null || prefix.getImage() == null) && suffix != null && suffix.getImage() != null){
        		String fieldName = suffix.getImage();
        		if (currentPathTaintedVariables.contains("this." + fieldName)){
        			currentPathTaintedVariables.add(variable);
        		}
        	}        		
        }
    }

    private String getMethod(Node node) {

        String method = getFullMethodName(node);        

        if (method.indexOf('.') != -1) {
            method = method.substring(method.indexOf('.') + 1);
        }

        return method;
    }
    
    private String getFullMethodName(Node node) {
    	ASTClassOrInterfaceType astClass = node.getFirstDescendantOfType(ASTClassOrInterfaceType.class);
        if (astClass != null) {
            return astClass.getImage();
        }
		ASTPrimaryPrefix prefix = node.getFirstChildOfType(ASTPrimaryPrefix.class);
		
		if (prefix != null) {
			ASTName astName = prefix.getFirstChildOfType(ASTName.class);
			if (astName != null && astName.getImage() != null) {
				return astName.getImage();
			}
		}
		if (prefix == null) {
			ASTName astName = node.getFirstDescendantOfType(ASTName.class);
			if (astName != null && astName.getImage() != null) {
				return astName.getImage();
			}
		}
		StringBuilder mName = new StringBuilder();
		List<ASTPrimarySuffix> suffixes = node.findChildrenOfType(ASTPrimarySuffix.class);
		for (ASTPrimarySuffix suffix : suffixes) {
			if (!suffix.hasDescendantOfType(ASTArguments.class) && suffix.getImage() != null) {
				if (mName.length() > 0) {
					mName.append(".");
				}
				mName.append(suffix.getImage());
			}
		}
		return mName.toString();		
    }
    
    private String getType(Node node, String method) {
        String methodMsg = "Utils::getType - {0}";
		
        String cannonicalName = "";
        Class<? extends Object> type = null;
		
        try {
            if (node instanceof ASTExpression) {				
                type = node.getFirstChildOfType(ASTPrimaryExpression.class).getFirstChildOfType(ASTName.class).getType();
            } else if (node instanceof ASTPrimaryExpression) {
            	ASTClassOrInterfaceType astClass = node.getFirstDescendantOfType(ASTClassOrInterfaceType.class);
                if (astClass != null) {					
                    type = astClass.getType();
                } else {	
                	ASTPrimaryPrefix prefix = node.getFirstChildOfType(ASTPrimaryPrefix.class);
                	ASTName astName = prefix.getFirstChildOfType(ASTName.class);        	
                	if (astName != null) {
                		type = astName.getType();
                		if (type == null) {
                			String parameterName = astName.getImage();
                			if (parameterName.indexOf('.') > 0) {
                				parameterName = parameterName.substring(0, parameterName.indexOf('.'));
                			}
                			type = functionParameterTypes.get(parameterName);
                		}
                	}
                	else {
                		ASTPrimarySuffix suffix = node.getFirstChildOfType(ASTPrimarySuffix.class);
                		type = fieldTypes.get(suffix.getImage());
                	}
                    
                }
            } else if (node instanceof ASTName) {
                type = ((ASTName) node).getType();
            }            
			if (type != null) {
				cannonicalName = type.getCanonicalName();
			}
			else {
				cannonicalName = "UNKNOWN_TYPE";
			}
        } catch (Exception ex1) {
    		
            LOG.log(Level.INFO, methodMsg,
                    "Unable to get type for " + method + " at "
                    + rc.getSourceCodeFilename() + " (" + node.getBeginLine()
                    + ")");
            cannonicalName = "UNKNOWN_TYPE";
        }
		
        return cannonicalName;
    }
    


    private void analyzeVariable(String variableName, List<ASTName> listOfAstNames) {
		for (ASTName name : listOfAstNames) {
			String var = name.getImage();
			if (var.indexOf('.') != -1) {
				var = var.substring(var.indexOf('.') + 1);
			}
			if (isTaintedVariable(var) || isSource(getType(name, var), var)) {
				this.currentPathTaintedVariables.add(variableName);
			}

		}

    }

}