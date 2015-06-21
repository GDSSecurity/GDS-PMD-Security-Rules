/*
 * This code is licensed under the Reciprocal Public License 1.5 (RPL1.5)http://www.opensource.org/licenses/rpl1.5
 * 
 * Copyright (c) 2012 Gotham Digital Science, LLC -- All Rights Reserved
 *
 */


package com.gdssecurity.pmd;


import java.io.BufferedReader;
import java.io.Closeable;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.util.HashSet;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

import net.sourceforge.pmd.RuleContext;
import net.sourceforge.pmd.lang.ast.Node;
import net.sourceforge.pmd.lang.java.ast.ASTClassOrInterfaceType;
import net.sourceforge.pmd.lang.java.ast.ASTExpression;
import net.sourceforge.pmd.lang.java.ast.ASTFieldDeclaration;
import net.sourceforge.pmd.lang.java.ast.ASTName;
import net.sourceforge.pmd.lang.java.ast.ASTPrimaryExpression;
import net.sourceforge.pmd.lang.java.ast.ASTPrimaryPrefix;
import net.sourceforge.pmd.lang.java.ast.ASTPrimarySuffix;
import net.sourceforge.pmd.lang.java.ast.ASTTypeDeclaration;
import net.sourceforge.pmd.lang.java.ast.ASTVariableDeclarator;
import net.sourceforge.pmd.lang.java.ast.ASTVariableDeclaratorId;


public final class Utils {

    private static final Logger LOG = Logger.getLogger("com.gdssecurity.pmd.rules");
	
    private Utils () {
    	throw new AssertionError("No instances allowed");
    }
    
    @SuppressWarnings("resource")
	public static String getCodeSnippet(String fileName, int start, int end) {
        StringBuilder sb = new StringBuilder();
        BufferedReader br = null;
        try {
        	br = new BufferedReader(new FileReader(new File(fileName)));
            int lintCtr = 1;

            for (String s = null; (s = br.readLine()) != null;) {
                if (lintCtr >= start && lintCtr <= end) {
                    sb.append(s);
                }
                lintCtr++;
            }
        } catch (FileNotFoundException fnfe) {
            LOG.warning(
                    "Unable to find the file " + fileName
                    + ". Ensure PMD short file names option is disabled.");
        } catch (IOException ioe) {
            LOG.warning(
                    "Unexpected error while retrieving code snippet from "
                            + fileName + " " + ioe.getStackTrace().toString());
        } 
        finally {
        	close(br);
        }
        return sb.toString();
    }
	
    public static String getType(Node node, RuleContext rc, String method) {
        String methodMsg = "Utils::getType - {0}";
		
        String cannonicalName = "";
        Class<? extends Object> type = null;
		
        try {
            if (node instanceof ASTExpression) {				
                type = node.getFirstChildOfType(ASTPrimaryExpression.class).getFirstChildOfType(ASTName.class).getType();
            } else if (node instanceof ASTPrimaryExpression) {
                if (node.hasDescendantOfType(ASTClassOrInterfaceType.class)) {					
                    type = node.getFirstDescendantOfType(ASTClassOrInterfaceType.class).getType();
                } else {	
                	ASTPrimaryPrefix prefix = node.getFirstChildOfType(ASTPrimaryPrefix.class);
                	ASTName astName = prefix.getFirstChildOfType(ASTName.class);        	
                	if (astName != null) {
                		type = node.getFirstDescendantOfType(ASTName.class).getType();
                	}
                	else {
                		ASTPrimarySuffix suffix = node.getFirstChildOfType(ASTPrimarySuffix.class);
                		type = getFieldType(node, suffix.getImage());
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
	
    private static Class<? extends Object> getFieldType(Node node, String fieldName) {
		ASTTypeDeclaration classDeclaration = node.getFirstParentOfType(ASTTypeDeclaration.class);
		if (classDeclaration == null) {
			return null;
		}
		List<ASTFieldDeclaration> fields = classDeclaration.findDescendantsOfType(ASTFieldDeclaration.class);
		for (ASTFieldDeclaration field : fields) {
			ASTVariableDeclarator declarator = field.getFirstChildOfType(ASTVariableDeclarator.class);
			ASTVariableDeclaratorId name1 = declarator.getFirstChildOfType(ASTVariableDeclaratorId.class);
			if (name1 != null) {
				String name = name1.getImage();
				if (name.equals(fieldName)) {
					return name1.getType();
				}
			}
			
		}    	
		return null;
	}

	public static HashSet<String> arrayAsHashSet(String[] array) {
        HashSet<String> hashSet = new HashSet<String>(array.length);
        int nbItem = 0;

        while (nbItem < array.length) {
            String str = array[nbItem++];

            hashSet.add(str);
        }
        return hashSet;
    }
    
    public static void close(Closeable closeable) {
    	try {
    		if (closeable != null) {
    			closeable.close();
    		}
    	}
    	catch (Exception e) {
    		//
    	}
    }
    public static void close(Closeable... closeables) {
    	for (Closeable closeable: closeables) {
    		close (closeable);
    	}
    }
}
