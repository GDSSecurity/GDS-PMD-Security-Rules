package test.com.gdssecurity.pmd.webapp.servlet.authz;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.*;

public class TestRoleAuthZServlet extends HttpServlet {

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	public void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {

         if (req.isUserInRole("admin")) { // role-based authorization check
            // Do admin stuff
        } else {
            // Access denied
        }
        
	}
	
	public void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {

        req.isUserInRole("admin"); // inadequate role-based authorization check
        // Do admin stuff
              
	}
	
	public void doPut(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {

        // missing role-based authorization check
        // Do admin stuff
              
	}
}
