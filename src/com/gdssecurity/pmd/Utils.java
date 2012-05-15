/*
 * This code is licensed under the Reciprocal Public License 1.5 (RPL1.5)http://www.opensource.org/licenses/rpl1.5
 * 
 * Copyright (c) 2012 Gotham Digital Science, LLC -- All Rights Reserved
 *
 */


package com.gdssecurity.pmd;


import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.util.HashSet;
import java.util.logging.Level;
import java.util.logging.Logger;

import net.sourceforge.pmd.RuleContext;
import net.sourceforge.pmd.ast.ASTClassOrInterfaceType;
import net.sourceforge.pmd.ast.ASTExpression;
import net.sourceforge.pmd.ast.ASTName;
import net.sourceforge.pmd.ast.ASTPrimaryExpression;
import net.sourceforge.pmd.ast.SimpleNode;


public class Utils {

    private static final Logger LOG = Logger.getLogger(
            "com.gdssecurity.pmd.rules");
	
    public static String getCodeSnippet(String fileName, int start, int end) {
        StringBuffer sb = new StringBuffer();
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
        
        return sb.toString();
    }
	
    public static String getType(SimpleNode node, RuleContext rc, String method) {
        String methodMsg = "Utils::getType - {0}";
		
        String cannonicalName = "";
        Class type = null;
		
        try {
            if (node instanceof ASTExpression) {
				
                type = node.getFirstChildOfType(ASTPrimaryExpression.class).getFirstChildOfType(ASTName.class).getType();
            } else if (node instanceof ASTPrimaryExpression) {
                if (node.containsChildOfType(ASTClassOrInterfaceType.class)) {
					
                    type = node.getFirstChildOfType(ASTClassOrInterfaceType.class).getType();
                } else {
					
                    type = node.getFirstChildOfType(ASTName.class).getType();
                }
            } else if (node instanceof ASTName) {
                type = ((ASTName) node).getType();
            }
			
            cannonicalName = type.getCanonicalName();
        } catch (Exception ex1) {
    		
            LOG.log(Level.INFO, methodMsg,
                    "Unable to get type for " + method + " at "
                    + rc.getSourceCodeFilename() + " (" + node.getBeginLine()
                    + ")");
            cannonicalName = "UNKNOWN_TYPE";
        }
		
        return cannonicalName;
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
}
