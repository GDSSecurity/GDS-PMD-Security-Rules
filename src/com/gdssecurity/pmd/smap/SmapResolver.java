/*
 * This code is licensed under the Reciprocal Public License 1.5 (RPL1.5)http://www.opensource.org/licenses/rpl1.5
 * 
 * Copyright (c) 2012 Gotham Digital Science, LLC -- All Rights Reserved
 *
 */


package com.gdssecurity.pmd.smap;


import java.util.*;
import java.io.IOException;


public class SmapResolver {
    
    private static final String SMAP_HEADER = "SMAP"; 
    
    private static final String DEFAULT_STRATUM = "JSP"; 
    
    private static final String STRATUM_SECTION = "*S JSP"; 
    
    private static final String LINE_SECTION = "*L"; 
    
    private static final String FILE_SECTION = "*F"; 
        
    private static final String END_SECTION = "*E"; 
    
    private static final String FID_DELIM = "#"; 

    private SmapReader reader = null;
    
    private boolean resolved = false;
    
    private String defaultStratum = null;
    
    private String outputFileName = null;
    
    private Hashtable fsection = new Hashtable(3);
    
    private boolean fsection_sourceNameSourcePath = false;
    
    private Map jsp2java = new TreeMap();
    
    private Map java2jsp = new TreeMap();

    public SmapResolver(SmapReader reader) {
        this.resolved = resolve(reader.readSmap());
        this.reader = reader;
    }

    public String toString() {
        return reader.toString();
    }
        
    private boolean resolve(String smap) {
        
        boolean fileSection = false;        
        boolean lineSection = false;        
        boolean jspStratumSection = false;  

        if (smap == null) {
            return false;
        }
        
        StringTokenizer st = new StringTokenizer(smap, "\n", false);
        
        int counter = 1;
        int sectionCounter = 0; 
        
        String fileIndex = null;
        
        boolean cont = true;
        
        while (st.hasMoreTokens()) {
            String token = st.nextToken();
            
            if (counter == 1) {         
                if (!SMAP_HEADER.equals(token)) {
                    return false;
                }
            } else if (counter == 2) {  
                outputFileName = token;  
            } else if (counter == 3) {  
                defaultStratum = token;
            } else if (STRATUM_SECTION.equals(token)) {
                jspStratumSection = true;
            } else if (FILE_SECTION.equals(token) && (jspStratumSection)) {
                fileSection = true;
                sectionCounter = 0;
            } else if (LINE_SECTION.equals(token) && (jspStratumSection)) {
                fileSection = false;
                lineSection = true;
                sectionCounter = 0;
                fileIndex = "0";
            } else if (END_SECTION.equals(token) && (jspStratumSection)) {
                cont = false;
                lineSection = false;
                fileSection = false;
                sectionCounter = 0;
            }

            if (fileSection) {
            	
                if (sectionCounter != 0) { 
                    storeFile(token);
                }
                sectionCounter++;
            }
            
            if (lineSection) { 
                if (sectionCounter != 0) {  
                    int hashPresent = token.indexOf(FID_DELIM);

                    if (hashPresent > -1) { 
                        fileIndex = token.substring(hashPresent + 1,
                                token.indexOf(':'));
                        if (fileIndex.indexOf(",") != -1) {
                            fileIndex = fileIndex.substring(0,
                                    fileIndex.indexOf(","));
                        }
                    }
                    
                    storeLine(token, fileIndex);
                }
                sectionCounter++;
            }
            counter++;
        }
        
        this.resolved = sanityCheck();
        return this.resolved;
    }
    
    private void storeFile(String token) {
    	
        String sourceName = "";
        String sourcePath = "";
        String id = "";
        boolean sourceNameSourcePath = false;
    	
        if (token.indexOf("+") != -1) {
            int firstSpaceIndex = token.indexOf(" ");
            int secondSpaceIndex = token.lastIndexOf(" ");

            id = token.substring(firstSpaceIndex + 1, secondSpaceIndex);
            sourceName = token.substring(secondSpaceIndex + 1);
            sourceNameSourcePath = true;
        } else if (fsection_sourceNameSourcePath) {
            sourcePath = token;
            if (token.lastIndexOf("/") != -1) {
                sourceName = sourcePath.substring(token.lastIndexOf("/") + 1,
                        sourcePath.length());
                id = getIndexByFileName(sourceName);
            } else {
                sourceName = sourcePath;
                id = getIndexByFileName(sourceName);
            }
    		
        }
    	
        fsection.put(id,
                (fsection_sourceNameSourcePath) ? sourcePath : sourceName);
        
        fsection_sourceNameSourcePath = (sourceNameSourcePath) ? true : false;
    }

    private void storeLine(String token, String fileIndex) {
        int delimIndex = token.indexOf(":");
        
        String jspLine = token.substring(0, delimIndex);
        String javaLine = token.substring(delimIndex + 1);
        
        int hashPresent = jspLine.indexOf(FID_DELIM);
        int commaPresent = jspLine.indexOf(',');

        int jspIndex = 0;    
        int repeatCount = 0;

        if (commaPresent != -1) {
            repeatCount = Integer.parseInt(jspLine.substring(commaPresent + 1));
            if (hashPresent == -1) {
                jspIndex = Integer.parseInt(jspLine.substring(0, commaPresent));
            } else {
                jspIndex = Integer.parseInt(jspLine.substring(0, hashPresent));
            }
        } else {
            if (hashPresent == -1) {
                jspIndex = Integer.parseInt(jspLine);
            } else {
                jspIndex = Integer.parseInt(jspLine.substring(0, hashPresent));
            }
            repeatCount = 1;
        }
        
        commaPresent = javaLine.indexOf(',');
        
        int outputIncrement;
        int javaIndex;

        if (commaPresent != -1) {
            outputIncrement = Integer.parseInt(
                    javaLine.substring(commaPresent + 1));
            javaIndex = Integer.parseInt(javaLine.substring(0, commaPresent));
        } else {
            outputIncrement = 1;
            javaIndex = Integer.parseInt(javaLine);
        }
        
        for (int i = 0; i < repeatCount; i++) {
            int jspL = jspIndex + i;
            int javaL = javaIndex + (i * outputIncrement);
            
            jspLine = Integer.toString(jspL).concat(FID_DELIM).concat(fileIndex);
            javaLine = Integer.toString(javaL);
            if (!jsp2java.containsKey(jspLine)) { 
                jsp2java.put(jspLine, javaLine);
            }
            
            jspLine = Integer.toString(jspL).concat("#").concat(fileIndex);
            
            javaLine = Integer.toString(javaL);
            
            if (!java2jsp.containsKey(javaLine)) { 
                java2jsp.put(javaLine, jspLine);
            }
        }
    }
    
    private boolean sanityCheck() {   
        if (!DEFAULT_STRATUM.equals(defaultStratum)) {
            return false;
        }
        if (!(outputFileName.endsWith(".java"))) {
            return false;
        }
        if (fsection.isEmpty()) {
            return false;
        }
        if (jsp2java.isEmpty()) {
            return false;
        }   
        if (java2jsp.isEmpty()) {
            return false;
        }   
        return true;
    }
    
    private String getFileNameByIndex(String index) {
        return (String) fsection.get(index);
    }
    
    private String getIndexByFileName(String fname) {
        Set s = fsection.entrySet();
        Iterator i = s.iterator();

        while (i.hasNext()) {
            Map.Entry mentry = (Map.Entry) i.next();
            String value = (String) mentry.getValue();
            
            if (value.equalsIgnoreCase(fname)) {
                return mentry.getKey().toString();
            }
        }
        return null;
    }
    
    public String getSourcePath(String fname) {
        Set s = fsection.entrySet();
        Iterator i = s.iterator();

        while (i.hasNext()) {
            Map.Entry mentry = (Map.Entry) i.next();
            String value = (String) mentry.getValue();
            int delim = value.lastIndexOf(":");
            String sourceName = value.substring(0, delim);
            String sourcePath = value.substring(delim + 1);
            
            if (sourceName.equalsIgnoreCase(fname)) {
                return sourcePath;
            }
        }
        return null;
    }

    public boolean isResolved() {
        return this.resolved;
    }
    
    public Map getFileNames() {
        Hashtable h = new Hashtable(fsection.size());
        Collection c = fsection.values();
        Iterator i = c.iterator();
        int counter = 0;

        while (i.hasNext()) {
            h.put(new Integer(counter++), i.next());
        }
        return h;
    }
    
    public String getPrimaryJspFileName() {
        TreeMap tm = new TreeMap(fsection);
        Object o = tm.firstKey();
        String s = (String) fsection.get(o);
        
        return s;
    }

    public boolean hasIncludedFiles() {
        return (fsection.size() > 1);
    }
    
    public String getJavaLineType(int line, int col) {
        
        return null;
    }
    
    public boolean isEmpty() {
        return jsp2java.isEmpty();  
    }

    public String getJspFileName(int line, int col) {
        String key = Integer.toString(line);
        String value = (String) java2jsp.get(key);
        
        if (value == null) {
            return null;
        }
        String index = value.substring(value.indexOf(FID_DELIM) + 1);
        
        return getFileNameByIndex(index);
    }
    
    public int mangle(String jspFileName, int line, int col) {
        String fileIndex = getIndexByFileName(jspFileName);

        if (fileIndex == null) {
            return -1;
        }
        String key = "".concat(Integer.toString(line)).concat("#").concat(
                fileIndex);
        String value = (String) jsp2java.get(key);

        if (value == null) {
            return -1;
        }
        return Integer.parseInt(value);
    }

    public int unmangle(int line, int col) {
        String key = Integer.toString(line);
        String value = (String) java2jsp.get(key);

        if (value == null) {
            return -1;
        }
        int jspline = Integer.parseInt(value.substring(0, value.indexOf("#")));

        return jspline;
    }
    
}
