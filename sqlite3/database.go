package sqlite3

import (
	"database/sql"
	"fmt"
	_ "github.com/mattn/go-sqlite3"
	"path/filepath"
	"strconv"
	"time"
)

const DatabaseFile = "database.db"

// HandleDatabase 查询
func HandleDatabase(dbPath string) (string, string, error) {
	db, err := sql.Open("sqlite3", filepath.Join(dbPath, DatabaseFile))
	if err != nil {
		return "", "", err
	}
	defer db.Close()

	// 执行特定的SQL语句，只查询state为0的记录
	sqlStatement := "SELECT * FROM DBTABLESMS WHERE STATE = 0 ORDER BY TIME DESC LIMIT 1"
	rows, err := db.Query(sqlStatement)
	if err != nil {
		return "", "", err
	}
	defer rows.Close()

	// 获取查询结果
	var idx, phone, smsbox, state, timeStr, content string
	for rows.Next() {
		err = rows.Scan(&idx, &phone, &smsbox, &state, &timeStr, &content)
		if err != nil {
			return "", "", err
		}
	}

	if err = rows.Err(); err != nil {
		return "", "", err
	}

	// 如果timeStr不为空，那么将时间戳转换为整数并格式化
	var timeFormatted string
	if timeStr != "" {
		timeInt, err := strconv.ParseInt(timeStr, 10, 64)
		if err != nil {
			return "", "", err
		}

		// 将时间戳转换为人类可读的时间格式
		timeFormatted = time.Unix(timeInt, 0).Format("2006-01-02 15:04:05")
	}

	// 返回包含关键词及其对应值的字符串
	result := fmt.Sprintf("IDX: %s\n手机号: %s\nSMSBOX: %s\nSTATE: %s\n时间: %s\n内容: %s", idx, phone, smsbox, state, timeFormatted, content)

	return result, idx, nil
}

// UpdateState 更新
func UpdateState(dbPath string, idx string) error {
	db, err := sql.Open("sqlite3", filepath.Join(dbPath, DatabaseFile))
	if err != nil {
		return err
	}
	defer func(db *sql.DB) {
		err := db.Close()
		if err != nil {

		}
	}(db)

	_, err = db.Exec(`UPDATE DBTABLESMS SET STATE = 1 WHERE IDX = ?`, idx)
	if err != nil {
		return err
	}

	return nil
}
