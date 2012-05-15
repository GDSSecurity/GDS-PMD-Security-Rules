/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE327_Use_Broken_Crypto__basic_01.java
Label Definition File: CWE327_Use_Broken_Crypto__basic.label.xml
Template File: point-flaw-01.tmpl.java
*/
/*
* @description
* CWE: 327 Use of Broken or Risky Cryptographic Algorithm
* Sinks:
*    GoodSink: use AES
*    BadSink : use DES
* Flow Variant: 01 Baseline
*
* */

package testcases.CWE327_Use_Broken_Crypto;

import testcasesupport.*;

import javax.servlet.http.*;
import java.io.*;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

public class CWE327_Use_Broken_Crypto__basic_01 extends AbstractTestCase
{

    public void bad() throws Throwable
    {

        java.util.logging.Logger log_bsnk = java.util.logging.Logger.getLogger("local-logger");

        IO.writeLine("Enter string for encryption: ");

        BufferedReader bufread2 = null;
        InputStreamReader inread2 = null;
        try
        {
            inread2 = new InputStreamReader(System.in);
            bufread2 = new BufferedReader(inread2);
            String str = bufread2.readLine();

            /* FLAW: Insecure cryptographic algorithm (DES) */
            Cipher des = Cipher.getInstance("DES");
            SecretKey key = KeyGenerator.getInstance("DES").generateKey();
            des.init(Cipher.ENCRYPT_MODE, key);

            byte[] enc_str = des.doFinal(str.getBytes());

            IO.writeLine(IO.toHex(enc_str));
        }
        catch(IOException e)
        {
            log_bsnk.warning("Error reading from console");
        }
        finally
        {
            try
            {
                if( bufread2 != null )
                {
                    bufread2.close();
                }
            }
            catch( IOException e )
            {
                log_bsnk.warning("Error closing bufread2");
            }
            finally
            {
                try
                {
                    if( inread2 != null )
                    {
                        inread2.close();
                    }
                }
                catch( IOException e )
                {
                    log_bsnk.warning("Error closing inread2");
                }
            }
        }

    }

    public void good() throws Throwable
    {
        good1();
    }

    private void good1() throws Throwable
    {

        java.util.logging.Logger log_gsnk = java.util.logging.Logger.getLogger("local-logger");

        IO.writeLine("Enter string for encryption: ");

        BufferedReader bufread2 = null;
        InputStreamReader inread2 = null;
        try
        {
            inread2 = new InputStreamReader(System.in);
            bufread2 = new BufferedReader(inread2);
            String str = bufread2.readLine();

            /* FIX: Secure cryptographic algorithm (AES) */
            Cipher aes = Cipher.getInstance("AES");
            KeyGenerator kg = KeyGenerator.getInstance("AES");
            kg.init(128);
            SecretKey key = kg.generateKey();
            aes.init(Cipher.ENCRYPT_MODE, key);

            byte[] enc_str = aes.doFinal(str.getBytes());

            IO.writeLine(IO.toHex(enc_str));
        }
        catch(IOException e)
        {
            log_gsnk.warning("Error reading from console");
        }
        finally
        {
            try
            {
                if( bufread2 != null )
                {
                    bufread2.close();
                }
            }
            catch( IOException e )
            {
                log_gsnk.warning("Error closing bufread2");
            }
            finally
            {
                try
                {
                    if( inread2 != null )
                    {
                        inread2.close();
                    }
                }
                catch( IOException e )
                {
                    log_gsnk.warning("Error closing inread2");
                }
            }
        }

    }

    /* Below is the main(). It is only used when building this testcase on
       its own for testing or for building a binary to use in testing binary
       analysis tools. It is not used when compiling all the testcases as one
       application, which is how source code analysis tools are tested. */
    public static void main(String[] args) throws ClassNotFoundException,
           InstantiationException, IllegalAccessException
    {
        mainFromParent(args);
    }
}

