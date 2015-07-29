/*
 * This code is licensed under the Reciprocal Public License 1.5 (RPL1.5)http://www.opensource.org/licenses/rpl1.5
 * 
 * Copyright (c) 2012 Gotham Digital Science, LLC -- All Rights Reserved
 *
 */


package com.gdssecurity.pmd.rules.dfa;


import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

import net.sourceforge.pmd.PropertyDescriptor;
import net.sourceforge.pmd.RuleContext;
import net.sourceforge.pmd.lang.ast.Node;
import net.sourceforge.pmd.lang.dfa.DataFlowNode;
import net.sourceforge.pmd.lang.dfa.NodeType;
import net.sourceforge.pmd.lang.dfa.VariableAccess;
import net.sourceforge.pmd.lang.dfa.pathfinder.CurrentPath;
import net.sourceforge.pmd.lang.dfa.pathfinder.DAAPathFinder;
import net.sourceforge.pmd.lang.dfa.pathfinder.Executable;
import net.sourceforge.pmd.lang.java.ast.ASTArgumentList;
import net.sourceforge.pmd.lang.java.ast.ASTArguments;
import net.sourceforge.pmd.lang.java.ast.ASTAssignmentOperator;
import net.sourceforge.pmd.lang.java.ast.ASTClassOrInterfaceBody;
import net.sourceforge.pmd.lang.java.ast.ASTClassOrInterfaceBodyDeclaration;
import net.sourceforge.pmd.lang.java.ast.ASTClassOrInterfaceDeclaration;
import net.sourceforge.pmd.lang.java.ast.ASTClassOrInterfaceType;
import net.sourceforge.pmd.lang.java.ast.ASTConstructorDeclaration;
import net.sourceforge.pmd.lang.java.ast.ASTExpression;
import net.sourceforge.pmd.lang.java.ast.ASTFieldDeclaration;
import net.sourceforge.pmd.lang.java.ast.ASTFormalParameter;
import net.sourceforge.pmd.lang.java.ast.ASTFormalParameters;
import net.sourceforge.pmd.lang.java.ast.ASTMethodDeclaration;
import net.sourceforge.pmd.lang.java.ast.ASTMethodDeclarator;
import net.sourceforge.pmd.lang.java.ast.ASTName;
import net.sourceforge.pmd.lang.java.ast.ASTPrimaryExpression;
import net.sourceforge.pmd.lang.java.ast.ASTPrimaryPrefix;
import net.sourceforge.pmd.lang.java.ast.ASTPrimarySuffix;
import net.sourceforge.pmd.lang.java.ast.ASTStatementExpression;
import net.sourceforge.pmd.lang.java.ast.ASTType;
import net.sourceforge.pmd.lang.java.ast.ASTVariableDeclarator;
import net.sourceforge.pmd.lang.java.ast.ASTVariableDeclaratorId;
import net.sourceforge.pmd.lang.java.ast.ASTVariableInitializer;
import net.sourceforge.pmd.lang.rule.properties.StringMultiProperty;

import org.apache.commons.lang3.StringUtils;
import org.jaxen.JaxenException;

import com.gdssecurity.pmd.Utils;
import com.gdssecurity.pmd.rules.BaseSecurityRule;


public class DfaSecurityRule extends BaseSecurityRule  implements Executable {

    private static final String UNKNOWN_TYPE = "UNKNOWN_TYPE";
	private Set<String> currentPathTaintedVariables;
    private Set<String> functionParameterTainted = new HashSet<String>();
    private Set<String> fieldTypesTainted = new HashSet<String>();
    
    private Map<String, Class<?>> fieldTypes;
    private Map<String, Class<?>> functionParameterTypes;
    private Set<String> sinks;
    private Set<String> sanitizers;
	


    private final PropertyDescriptor<String[]> sinkDescriptor = new StringMultiProperty("sinks", "TODO",
            new String[] { "" }, 1.0f, '|');
    
    private final PropertyDescriptor<String[]> sanitizerDescriptor = new StringMultiProperty("sanitizers", "TODO", 
    		new String[] { "" }, 1.0f, '|');

    private RuleContext rc;
    private int methodDataFlowCount;
	
    private List<DataFlowNode> additionalDataFlowNodes = new ArrayList<DataFlowNode>();
	
    private static final int MAX_DATAFLOWS = 1000;
    
    public DfaSecurityRule () {
    	super();

    	this.propertyDescriptors.add(this.sinkDescriptor);
    	this.propertyDescriptors.add(this.sanitizerDescriptor);
    }
	
    @Override
    protected void init() {
    	super.init();
    	this.sinks = Utils.arrayAsSet(getProperty(this.sinkDescriptor));
        this.sanitizers = Utils.arrayAsSet(getProperty(this.sanitizerDescriptor));
    }




	protected boolean isSanitizerMethod(String type, String method) {
		return this.sanitizers.contains(type+"."+method);
	}
    private boolean isSink(String objectType, String objectMethod) {
        return this.sinks.contains(objectType + "." + objectMethod);
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
        	//
        }
    }

    @Override
	public void execute(CurrentPath currentPath) {

        this.methodDataFlowCount++;
        this.currentPathTaintedVariables = new HashSet<String>();
        this.currentPathTaintedVariables.addAll(this.fieldTypesTainted);
        this.currentPathTaintedVariables.addAll(this.functionParameterTainted);
        
        if (this.methodDataFlowCount < MAX_DATAFLOWS) {
            for (Iterator<DataFlowNode> iterator = currentPath.iterator(); iterator.hasNext();) {
                DataFlowNode iDataFlowNode = iterator.next();
                Node node = iDataFlowNode.getNode();
                if (node instanceof ASTMethodDeclaration || node instanceof ASTConstructorDeclaration) {                	
                    this.currentPathTaintedVariables = new HashSet<String>();                    
                    addMethodParamsToTaintedVariables(node);
                    addClassFieldsToTaintedVariables(node);
                    this.currentPathTaintedVariables.addAll(this.fieldTypesTainted);
                    this.currentPathTaintedVariables.addAll(this.functionParameterTainted);
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
		this.fieldTypesTainted = new HashSet<String>();
		
		ASTClassOrInterfaceBody astBody = node.getFirstParentOfType(ASTClassOrInterfaceBody.class);
		if (astBody == null) {
			return;
		}
		
		List<ASTClassOrInterfaceBodyDeclaration> declarations = astBody.findChildrenOfType(ASTClassOrInterfaceBodyDeclaration.class);
		for (ASTClassOrInterfaceBodyDeclaration declaration: declarations) {
			ASTFieldDeclaration field = declaration.getFirstChildOfType(ASTFieldDeclaration.class);
			if (field != null) {				
				Class<?> type = field.getType();
				ASTVariableDeclarator declarator = field.getFirstChildOfType(ASTVariableDeclarator.class);
				ASTVariableDeclaratorId name1 = declarator.getFirstChildOfType(ASTVariableDeclaratorId.class);
				if (name1 != null) {
					String name = name1.getImage();
					fieldTypes.put(name, type);
					if (!field.isFinal() && isUnsafeType(field.getType())) {
						fieldTypesTainted.add("this." + name);
					}
				}
			}
		}		
		
	}

	private void addMethodParamsToTaintedVariables(Node node) {
		this.functionParameterTypes = new HashMap<String, Class<?>>();
		this.functionParameterTainted = new HashSet<String>();
		ASTFormalParameters formalParameters = null;
		if (node instanceof ASTMethodDeclaration) {
			ASTMethodDeclarator declarator = node.getFirstChildOfType(ASTMethodDeclarator.class);
			formalParameters = declarator.getFirstChildOfType(ASTFormalParameters.class);
		}
		else if (node instanceof ASTConstructorDeclaration) {
			formalParameters = node.getFirstChildOfType(ASTFormalParameters.class); 
		}
		if (formalParameters == null) {
			return;
		}
		List<ASTFormalParameter> parameters = formalParameters.findChildrenOfType(ASTFormalParameter.class);       
		for (ASTFormalParameter parameter : parameters) {
			ASTType type = parameter.getTypeNode();
			ASTVariableDeclaratorId name1 = parameter.getFirstChildOfType(ASTVariableDeclaratorId.class);						
			String name = name1.getImage();
			if (name != null && type != null) {
				functionParameterTypes.put(name, type.getType());
			}
			if (name != null && isUnsafeType(type)){
				this.functionParameterTainted.add(name);
			}
		}
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
            type = getType(astMethod);    

            if (isSink(type, method)) {
                analyzeSinkMethodArgs(simpleNode);
            }
			
        } 
    }

    private void analyzeSinkMethodArgs(Node simpleNode) {
        ASTArgumentList argListNode = simpleNode.getFirstDescendantOfType(ASTArgumentList.class);    
        for(int i = 0; i < argListNode.jjtGetNumChildren(); i++) {
        	Node argument = argListNode.jjtGetChild(i);
        	if (isTainted(argument)){
        		addSecurityViolation(this, this.rc, simpleNode, getMessage(), "");
        	}
        } 		
    }



    private boolean isMethodCall(Node node) {
        ASTArguments arguments = node.getFirstDescendantOfType(ASTArguments.class);
        return arguments != null;
    }

	private void handleVariableDefinition(DataFlowNode iDataFlowNode, String variable) {
		Node simpleNode = iDataFlowNode.getNode();
		Class<?> clazz = String.class;
		
		
		Node primaryExpression = simpleNode.jjtGetChild(0);
		if (primaryExpression instanceof ASTPrimaryExpression) {
			Node primaryPrefix = primaryExpression.jjtGetChild(0);
			if (primaryPrefix instanceof ASTPrimaryPrefix) {
				clazz = ((ASTPrimaryPrefix) primaryPrefix).getType();
			}
		}
		if (primaryExpression instanceof ASTVariableDeclaratorId && simpleNode.jjtGetNumChildren() > 1) {
			Node initializer = simpleNode.jjtGetChild(1);
			if (initializer instanceof ASTVariableInitializer) {
				clazz = ((ASTVariableDeclaratorId)primaryExpression).getType();
			}
		}

		
		
				
		if (isTainted(simpleNode) && isUnsafeType(clazz)) {
			this.currentPathTaintedVariables.add(variable);
		}
	}
    
    private boolean isTainted(Node node2) {
    	List<ASTPrimaryExpression> primaryExpressions = getExp(node2);
    	for (ASTPrimaryExpression node: primaryExpressions) {
    		if (isMethodCall(node)) {
                String method = getMethod(node);
                String type = getType(node);
                if (isSanitizerMethod(type, method)) {
                	continue;
                }
                else if (isSource(type, method)) {
                    return true;
                } else if (isSink(type, method)) {
                    analyzeSinkMethodArgs(node);
                } 
                else if (isSafeType(getReturnType(node, type, method))){
                	continue;
                }
            } else if (node.hasDescendantOfType(ASTName.class)){
                List<ASTName> astNames = node.findDescendantsOfType(ASTName.class);
                if (analyzeVariable(astNames)){
                	return true;
                }
            }
            else {
            	ASTPrimaryPrefix prefix = node.getFirstChildOfType(ASTPrimaryPrefix.class);
            	ASTPrimarySuffix suffix = node.getFirstChildOfType(ASTPrimarySuffix.class);
            	if ((prefix == null || prefix.getImage() == null) && suffix != null && suffix.getImage() != null){
            		String fieldName = suffix.getImage();
            		if (currentPathTaintedVariables.contains("this." + fieldName)){
            			return true;
            		}
            	}        		
            }
    		boolean childsTainted = isTainted(node);
    		if (childsTainted) {
    			return true;
    		}
    	}
    	return false;
    	
    }
    
    private static Map<String, String> cacheReturnTypes = new HashMap<String, String>();
    
    private String getReturnType(ASTPrimaryExpression node, String type, String methodName) {
    	String realType = type;
    	try {
	    	Class<?> clazz = null;
	    	if (StringUtils.isBlank(realType) || UNKNOWN_TYPE.equals(realType)) {
	    		ASTClassOrInterfaceDeclaration type2 = node.getFirstParentOfType(ASTClassOrInterfaceDeclaration.class);
	    		if (type2 != null && type2.getType() != null){
	    			clazz = type2.getType();
	    			realType = clazz.getCanonicalName();
	    		}
	    	}
	    	
	    	if (cacheReturnTypes.containsKey(realType + "." + methodName)) {
	    		return cacheReturnTypes.get(realType + "." + methodName);
	    	}
	    	
	    	if (clazz == null && !StringUtils.isBlank(realType) && !UNKNOWN_TYPE.equals(realType)) {
	    		clazz = Class.forName(realType);
	    	}
	    	if (clazz != null) {		    	
		    	Set<Class<?>> methodReturnTypes = new HashSet<Class<?>>();
		    	for(Method method: clazz.getMethods()) {
		    		if (method.getName().equals(methodName)) {
		    			Class<?> returnType = method.getReturnType();
		    			if (returnType != null && !"void".equals(returnType.getCanonicalName())){
		    				methodReturnTypes.add(returnType);
		    			}
		    		}
		    	}
		    	if (methodReturnTypes.size() == 1) {
		    		String methodReturnType = methodReturnTypes.iterator().next().getCanonicalName();
		    		cacheReturnTypes.put(realType + "." + methodName, methodReturnType);
		    		return methodReturnType;
		    	}
	    	}
    	}
    	catch (Exception e) {
    		cacheReturnTypes.put(realType + "." + methodName, UNKNOWN_TYPE);
    		return UNKNOWN_TYPE;
    	}
    	catch (NoClassDefFoundError err) {
    		cacheReturnTypes.put(realType + "." + methodName, UNKNOWN_TYPE);
    		return UNKNOWN_TYPE;
    	}
    	catch (ExceptionInInitializerError err) {
    		cacheReturnTypes.put(realType + "." + methodName, UNKNOWN_TYPE);
    		return UNKNOWN_TYPE;
    	}
    	cacheReturnTypes.put(realType + "." + methodName, UNKNOWN_TYPE);
		return UNKNOWN_TYPE;
	}

	private List<ASTPrimaryExpression> getExp(Node node2) {
    	List<ASTPrimaryExpression> expressions = new ArrayList<ASTPrimaryExpression>();
    	for (int i=0; i < node2.jjtGetNumChildren(); i++) {
    		Node child = node2.jjtGetChild(i);
    		if (child instanceof ASTPrimaryExpression) {
    			expressions.add((ASTPrimaryExpression) child);
    		}
    		else {
    			expressions.addAll(getExp(child));
    		}
    	}
    	
		return expressions;
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
    
    private String getType(Node node) {
		
        String cannonicalName = "";
        Class<?> type = null;
		
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
				cannonicalName = UNKNOWN_TYPE;
			}
        } catch (Exception ex1) {    		
        	//
        }
		
        return cannonicalName;
    }
    



    
    private boolean analyzeVariable(List<ASTName> listOfAstNames) {
		for (ASTName name : listOfAstNames) {
			String var = name.getImage();
			if (var.indexOf('.') != -1) {
				var = var.substring(var.indexOf('.') + 1);
			}
			if (isTaintedVariable(var) || isSource(getType(name), var)) {
				return true;
			}
		}
		return false;
    }

}