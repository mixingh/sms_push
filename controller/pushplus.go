package controller

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
)

type PushPlusMessage struct {
	Token   string `json:"token"`
	Title   string `json:"title"`
	Content string `json:"content"`
}

func SendPushPlusMessage(token string, title string, content string) error {
	msg := PushPlusMessage{
		Token:   token,
		Title:   title,
		Content: content,
	}

	msgBytes, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("Error marshalling message: %v", err)
	}

	resp, err := http.Post("http://www.pushplus.plus/send", "application/json", bytes.NewBuffer(msgBytes))
	if err != nil {
		return fmt.Errorf("Error sending message: %v", err)
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("Error sending message, status code: %d", resp.StatusCode)
	}

	return nil
}

func SendDatabaseResult(token string, result string) error {
	title := "数据库查询结果"
	content := "以下是数据库查询结果：\n" + result
	return SendPushPlusMessage(token, title, content)
}
