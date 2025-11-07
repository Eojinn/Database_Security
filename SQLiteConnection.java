package org.example;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class SQLiteConnection {

    // 벤치마크 전용 데이터베이스 파일 이름
    private static final String DB_URL = "jdbc:sqlite:데이터베이스 이름";

    static {
        try {
            // SQLite JDBC 드라이버 로드
            Class.forName("org.sqlite.JDBC");
            System.out.println("SQLite JDBC 드라이버 로드 완료.");
        } catch (ClassNotFoundException e) {
            System.err.println("SQLite JDBC 드라이버를 찾을 수 없습니다.");
            e.printStackTrace();
            throw new RuntimeException("SQLite JDBC 드라이버 로드 실패", e);
        }
    }

    /**
     * SQLite 데이터베이스에 연결합니다.
     * @return Connection 객체
     * @throws SQLException 연결 오류 발생 시
     */
    public static Connection connect() throws SQLException {
        return DriverManager.getConnection(DB_URL);
    }

    /**
     * JDBC 리소스를 안전하게 닫습니다. (Connection, Statement, ResultSet)
     */
    public static void close(Connection conn, Statement stmt, ResultSet rs) {
        if (rs != null) {
            try { rs.close(); } catch (SQLException e) {
                System.err.println("ResultSet 닫기 오류: " + e.getMessage());
            }
        }
        if (stmt != null) {
            try { stmt.close(); } catch (SQLException e) {
                System.err.println("Statement 닫기 오류: " + e.getMessage());
            }
        }
        if (conn != null) {
            try { conn.close(); } catch (SQLException e) {
                System.err.println("Connection 닫기 오류: " + e.getMessage());
            }
        }
    }
}
