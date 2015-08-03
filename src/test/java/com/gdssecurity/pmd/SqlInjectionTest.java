package com.gdssecurity.pmd;


import org.junit.Assert;
import org.junit.Test;

public class SqlInjectionTest {

	
	@Test
	public void test1() throws Exception {
		Assert.assertEquals(1, PMDRunner.run("src/test/resources/sqlinjection1"));
	}

}
