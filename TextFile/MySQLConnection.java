package org.example;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

/**
 * MySQL 데이터베이스 연결을 관리하는 클래스입니다.
 * 연결, 테이블 생성, 샘플 데이터 삽입, 쿼리 실행 및 연결 종료 기능을 제공합니다.
 */
public class MySQLConnection {
    private String dbUrl;
    private String user;
    private String password;
    private Connection connection;
    // 🔑 테이블 이름 통일
    private static final String TABLE_NAME = "example_data";

    /**
     * MySQLConnection의 새 인스턴스를 생성합니다.
     *
     * @param dbUrl    데이터베이스 연결 URL
     * @param user     데이터베이스 사용자 이름
     * @param password 데이터베이스 비밀번호
     */
    public MySQLConnection(String dbUrl, String user, String password) {
        // 🔑 벤치마크 코드에서 설정했던 통일된 예시 DB 정보를 그대로 사용하도록 수정 (DB URL은 이미 생성자 인수로 받음)
        // 기존 코드: this.dbUrl = dbUrl;
        // 기존 코드: this.user = user;
        // 기존 코드: this.password = password;
        // 이 연결 관리 클래스 자체를 재사용 가능하도록 매개변수 기반으로 유지하되,
        // 이전에 통일했던 예시 값으로 주석을 추가합니다.
        this.dbUrl = dbUrl; // 예: "jdbc:mysql://localhost:3306/example_db"
        this.user = user;     // 예: "sample_user"
        this.password = password; // 예: "sample_password"
    }

    /**
     * 데이터베이스에 연결합니다.
     * 연결이 성공하면 테이블을 생성하고 샘플 데이터를 삽입합니다.
     */
    public void connect() {
        try {
            // JDBC 드라이버 로드
            Class.forName("com.mysql.cj.jdbc.Driver");
            // 데이터베이스 연결
            connection = DriverManager.getConnection(dbUrl, user, password);
            System.out.println("MySQL 데이터베이스에 연결되었습니다: " + dbUrl);
            createTableIfNotExist();
            insertSampleDataIfEmpty();
        } catch (ClassNotFoundException e) {
            System.err.println("MySQL JDBC 드라이버를 찾을 수 없습니다. Maven/Gradle 의존성을 확인하세요.");
            e.printStackTrace();
            throw new RuntimeException("MySQL JDBC 드라이버 로드 실패", e);
        } catch (SQLException e) {
            System.err.println("데이터베이스 연결 오류: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private void createTableIfNotExist() throws SQLException {
        // 🔑 테이블 이름과 컬럼 이름을 통일된 예시로 변경 ('category', 'value')
        String sql = "CREATE TABLE IF NOT EXISTS " + TABLE_NAME + " (\n"
                + " id INT AUTO_INCREMENT PRIMARY KEY,\n"
                + " category VARCHAR(255) NOT NULL,\n"
                + " value INT NOT NULL\n"
                + ");";
        try (Statement stmt = connection.createStatement()) {
            stmt.execute(sql);
            System.out.println("테이블 '" + TABLE_NAME + "'이(가) 존재하거나 생성되었습니다.");
        }
    }

    private void insertSampleDataIfEmpty() throws SQLException {
        String countSql = "SELECT COUNT(*) FROM " + TABLE_NAME + ";";
        try (Statement stmt = connection.createStatement();
             ResultSet rs = stmt.executeQuery(countSql)) {
            if (rs.next() && rs.getInt(1) == 0) {
                System.out.println("샘플 데이터 삽입 중...");
                // 🔑 샘플 데이터를 통일된 카테고리/값 데이터로 변경 (5개 행)
                String insertSql = "INSERT INTO " + TABLE_NAME + " (category, value) VALUES\n"
                        + "('Alpha', 101),\n"
                        + "('Beta', 202),\n"
                        + "('Gamma', 303),\n"
                        + "('Delta', 404),\n"
                        + "('Epsilon', 505);";
                try (Statement insertStmt = connection.createStatement()) {
                    insertStmt.execute(insertSql);
                    System.out.println("샘플 데이터 5개 삽입 완료.");
                }
            } else {
                System.out.println("테이블에 이미 데이터가 존재합니다. 샘플 데이터 삽입을 건너뜁니다.");
            }
        }
    }

    /**
     * SQL 쿼리를 실행하고 결과를 {@link ResultSet}으로 반환합니다.
     */
    public ResultSet executeQuery(String query) throws SQLException {
        if (connection == null) {
            throw new SQLException("데이터베이스에 연결되어 있지 않습니다.");
        }
        return connection.createStatement().executeQuery(query);
    }

    // 이 메서드를 추가하여 Connection 객체를 반환합니다.
    public Connection getConnection() {
        return connection;
    }

    /**
     * 데이터베이스 연결을 종료합니다.
     */
    public void close() {
        if (connection != null) {
            try {
                connection.close();
                System.out.println("데이터베이스 연결이 종료되었습니다.");
            } catch (SQLException e) {
                System.err.println("데이터베이스 연결 종료 오류: " + e.getMessage());
                e.printStackTrace();
            }
        }
    }
}