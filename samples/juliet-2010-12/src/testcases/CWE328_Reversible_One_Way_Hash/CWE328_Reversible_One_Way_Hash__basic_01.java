/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE328_Reversible_One_Way_Hash__basic_01.java
Label Definition File: CWE328_Reversible_One_Way_Hash__basic.label.xml
Template File: point-flaw-01.tmpl.java
*/
/*
* @description
* CWE: 328 Bad case uses insecure cryptographic hashing algorithm (MD5). Good case uses secure cryptographic hashing algorithm (SHA-512).
* Sinks:
*    GoodSink: sha512
*    BadSink : md5
* Flow Variant: 01 Baseline
*
* */

package testcases.CWE328_Reversible_One_Way_Hash;

import testcasesupport.*;

import java.security.GeneralSecurityException;
import java.security.MessageDigest;

public class CWE328_Reversible_One_Way_Hash__basic_01 extends AbstractTestCase
{

    public void bad() throws Throwable
    {

        String input = "Test Input";

        /* FLAW: Insecure cryptographic hashing algorithm (MD5) */
        MessageDigest hash = MessageDigest.getInstance("MD5");
        byte[] hashv = hash.digest(input.getBytes()); /* INCIDENTAL FLAW: Hard-coded input to hash algorithm */

        IO.writeLine(IO.toHex(hashv));

    }

    public void good() throws Throwable
    {
        good1();
    }

    private void good1() throws Throwable
    {

        String input = "Test Input";

        /* FIX: Secure cryptographic hashing algorithm (SHA-512) */
        MessageDigest hash = MessageDigest.getInstance("SHA-512");
        byte[] hashv = hash.digest(input.getBytes()); /* INCIDENTAL FLAW: Hard-coded input to hash algorithm */

        IO.writeLine(IO.toHex(hashv));

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

