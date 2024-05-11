package main

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"os"
	"sms_pushplus/controller"
	"sms_pushplus/sqlite3"
	"strings"
	"time"
)

const ConfigFile = "/home/root/r200/db_config.txt"

type Config struct {
	DBPath string
	Token  string
}

func main() {
	var config Config

	// 检查配置文件是否存在
	if _, err := os.Stat(ConfigFile); os.IsNotExist(err) {
		// 如果配置文件不存在，那么提示用户输入数据库文件的路径和pushplus的token
		reader := bufio.NewReader(os.Stdin)
		fmt.Print("配置文件不存在，请输入数据库文件的路径:")
		config.DBPath, _ = reader.ReadString('\n')
		config.DBPath = strings.TrimSpace(config.DBPath)

		fmt.Print("请输入pushplus的token:")
		config.Token, _ = reader.ReadString('\n')
		config.Token = strings.TrimSpace(config.Token)

		// 保存数据库文件的路径和pushplus的token到配置文件
		configContent := "url:" + config.DBPath + "\ntoken:" + config.Token
		err = ioutil.WriteFile(ConfigFile, []byte(configContent), 0644)
		if err != nil {
			fmt.Println(err)
			return
		}
	} else {
		// 如果配置文件存在，那么直接读取数据库文件的路径和pushplus的token
		content, err := ioutil.ReadFile(ConfigFile)
		if err != nil {
			fmt.Println(err)
			return
		}

		lines := strings.Split(string(content), "\n")
		if len(lines) < 2 {
			fmt.Println("配置文件格式错误，应包含url和token")
			return
		}
		config.DBPath = strings.TrimPrefix(lines[0], "url:")
		config.Token = strings.TrimPrefix(lines[1], "token:")
		fmt.Println("配置文件已找到，配置文件路径为:", ConfigFile, "，数据库路径为:", config.DBPath, "，pushplus的token为:", config.Token)
	}

	for {
		fmt.Println("尝试获取短信并推送...")

		// 调用sqlite3包中的HandleDatabase函数来处理数据库相关的操作
		content, idx, err := sqlite3.HandleDatabase(config.DBPath)
		if err != nil {
			fmt.Println(err)
			return
		}

		// 如果有查询结果，那么推送结果并更新state的值
		if idx != "" {
			//调用push-plus推送API
			err1 := controller.SendDatabaseResult(config.Token, content)
			if err1 != nil {
				fmt.Println(err)
				return
			}

			// 更新state的值
			err2 := sqlite3.UpdateState(config.DBPath, idx)
			if err2 != nil {
				fmt.Println(err)
				return
			}

			fmt.Println("短信获取并推送完成！请到pushplus公众号查收")
		} else {
			fmt.Println("没有新的短信需要推送")
		}

		// 暂停15秒
		time.Sleep(15 * time.Second)
	}
}
