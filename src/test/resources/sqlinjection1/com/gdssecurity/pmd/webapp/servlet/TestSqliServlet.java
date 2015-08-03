package sqlinjection1.com.gdssecurity.pmd.webapp.servlet;

import java.io.IOException;
import java.io.PrintWriter;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class TestSqliServlet extends HttpServlet {

  /**
	 * 
	 */
	private static final long serialVersionUID = 1720709420664861134L;

@Override
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
    	  if (rs != null) {
    		  rs.close();
    	  }
    	  if (stmt != null) {
    		  stmt.close();
    	  }
    	  if (con != null){
    		  con.close( );
    	  }
      }
      catch (SQLException ignored) { }
    }
  }

// Good
@Override
public void doPost(HttpServletRequest request, HttpServletResponse response)
                               throws ServletException, IOException {
    Connection con = null;
    PreparedStatement stmt = null;
    ResultSet rs = null;

    response.setContentType("text/html");
    PrintWriter out = response.getWriter( );

    String id = request.getParameter("id");

    try {

      Class.forName("oracle.jdbc.driver.OracleDriver");

      con = DriverManager.getConnection(
        "jdbc:oracle:thin:@dbhost:1521:ORCL", "user", "passwd");

      String strSql = "SELECT * FROM USERS WHERE ID = ?";
      stmt = con.prepareStatement(strSql);
      stmt.setString(1, id);

      

      rs = stmt.executeQuery();

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
    	  if (rs != null) {
    		  rs.close();
    	  }
    	  if (stmt != null) {
    		  stmt.close();
    	  }
    	  if (con != null){
    		  con.close( );
    	  }
      }
      catch (SQLException ignored) { }
    }
  }

	public void doGet1(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		Connection con = null;
		Statement stmt = null;
		ResultSet rs = null;

		response.setContentType("text/html");
		PrintWriter out = response.getWriter();

		String id = request.getParameter("id");

		try {

			Class.forName("oracle.jdbc.driver.OracleDriver");

			con = DriverManager.getConnection("jdbc:oracle:thin:@dbhost:1521:ORCL", "user", "passwd");

			String strSql = "SELECT * FROM USERS WHERE ID = '" + Integer.parseInt(id) + "'";

			stmt = con.createStatement();

			rs = stmt.executeQuery(strSql);

			out.println("<HTML><HEAD><TITLE>SqlInjectionExample</TITLE></HEAD>");
			out.println("<BODY>");
			while (rs.next()) {
				out.println(rs.getString("firstname") + "&nbsp;" + rs.getString("lastname"));
			}
			out.println("</BODY></HTML>");
		} catch (ClassNotFoundException e) {
			out.println("Couldn't load database driver: " + e.getMessage());
		} catch (SQLException e) {
			out.println("SQLException caught: " + e.getMessage());
		} finally {

			try {
				if (rs != null) {
					rs.close();
				}
				if (stmt != null) {
					stmt.close();
				}
				if (con != null) {
					con.close();
				}
			} catch (SQLException ignored) {
			}
		}
	}

}
