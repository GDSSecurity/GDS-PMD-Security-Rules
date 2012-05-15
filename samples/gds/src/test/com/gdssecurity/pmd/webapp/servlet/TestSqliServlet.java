package test.com.gdssecurity.pmd.webapp.servlet;

import java.io.*;
import java.sql.*;
import javax.servlet.*;
import javax.servlet.http.*;

public class TestSqliServlet extends HttpServlet {

  public void doGet(HttpServletRequest request, HttpServletResponse response)
                               throws ServletException, IOException {
    Connection con = null;
    Statement stmt = null;
    ResultSet rs = null;

    response.setContentType("text/html");
    PrintWriter out = response.getWriter( );

    String id = request.getParameter("id");

    try {

      Class.forName("oracle.jdbc.driver.OracleDriver");

      con = DriverManager.getConnection(
        "jdbc:oracle:thin:@dbhost:1521:ORCL", "user", "passwd");

      String strSql = "SELECT * FROM USERS WHERE ID = '" + id + "'";

      stmt = con.createStatement( );

      rs = stmt.executeQuery(strSql);

      out.println("<HTML><HEAD><TITLE>SqlInjectionExample</TITLE></HEAD>");
      out.println("<BODY>");
      while(rs.next( )) {
        out.println(rs.getString("firstname") + "&nbsp;" + rs.getString("lastname"));
      }
      out.println("</BODY></HTML>");
    }
    catch(ClassNotFoundException e) {
      out.println("Couldn't load database driver: " + e.getMessage( ));
    }
    catch(SQLException e) {
      out.println("SQLException caught: " + e.getMessage( ));
    }
    finally {

      try {
        if (con != null) con.close( );
      }
      catch (SQLException ignored) { }
    }
  }
}
