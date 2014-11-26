/*
 * This code is licensed under the Reciprocal Public License 1.5 (RPL1.5)http://www.opensource.org/licenses/rpl1.5
 * 
 * Copyright (c) 2012 Gotham Digital Science, LLC -- All Rights Reserved
 *
 */


package com.gdssecurity.pmd.smap;


import java.io.*;


public class SmapFileReader implements SmapReader {
        
    private File file;
    
    public SmapFileReader(java.io.File file) {
        this.file = file;
    }
    
    @Override
	public String toString() {
        if (file != null) {
            return file.toString();
        }
        return null;
    }
    
    @Override
	public String readSmap() {
        if (file != null) {
            try {
                FileReader fr = new FileReader(file);
                LineNumberReader lnr = new LineNumberReader(fr);
                String line = "";
                String out = "";

                while ((line = lnr.readLine()) != null) {
                    out = out.concat(line);
                    out = out.concat("\n");
                }
                return out;
            } catch (FileNotFoundException fne) {
                return null;
            } catch (IOException ioe) {
                return null;
            }
        }
        return null;
    }
 
}

