package org.example;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

/**
 * 모든 벤치마크 클래스에서 공통으로 사용되는 정적(Static) MySQL 연결 유틸리티 클래스입니다.
 * 인스턴스화 없이 바로 connect() 또는 close() 메서드를 호출할 수 있습니다.
 */
public final class MySQLConnection {

    // !!! 사용자 정의 필요: 실제 DB 접속 정보로 수정하세요. !!!
    private static final String DB_URL = "jdbc:mysql://localhost:주소/데이터베이스 이름";
    private static final String USER = "사용자 이름";
    private static final String PASSWORD = "비밀번호";

    /**
     * 외부에서 인스턴스 생성을 막기 위한 비공개 생성자
     */
    private MySQLConnection() {
        throw new UnsupportedOperationException("This is a utility class and cannot be instantiated");
    }

    /**
     * MySQL 데이터베이스에 연결하고 Connection 객체를 반환합니다.
     * @return 성공적으로 연결된 Connection 객체, 실패 시 null
     */
    public static Connection connect() {
        Connection connection = null;
        try {
            // 드라이버 로드는 MySQL Connector/J가 자동으로 처리합니다.
            connection = DriverManager.getConnection(DB_URL, USER, PASSWORD);
            System.out.println("MySQL 데이터베이스 연결 성공!");
        } catch (SQLException e) {
            System.err.println("MySQL 데이터베이스 연결 오류가 발생했습니다.");
            e.printStackTrace();
        }
        return connection;
    }

    /**
     * JDBC 리소스를 안전하게 닫습니다. (null 체크 포함)
     * @param conn Connection 객체
     * @param stmt Statement 또는 PreparedStatement 객체
     * @param rs ResultSet 객체
     */
    public static void close(Connection conn, Statement stmt, ResultSet rs) {
        if (rs != null) {
            try {
                rs.close();
            } catch (SQLException e) {
                System.err.println("ResultSet 닫기 오류: " + e.getMessage());
            }
        }
        if (stmt != null) {
            try {
                stmt.close();
            } catch (SQLException e) {
                System.err.println("Statement 닫기 오류: " + e.getMessage());
            }
        }
        // Connection은 최종적으로 닫습니다.
        if (conn != null) {
            try {
                conn.close();
            } catch (SQLException e) {
                System.err.println("Connection 닫기 오류: " + e.getMessage());
            }
        }
    }

    /**
     * Statement 또는 ResultSet만 닫을 때 편리하게 사용하기 위한 오버로드된 close 메서드.
     * @param stmt Statement 또는 PreparedStatement 객체
     * @param rs ResultSet 객체
     */
    public static void close(Statement stmt, ResultSet rs) {
        close(null, stmt, rs);
    }
}
