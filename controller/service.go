package controller

import (
	"fmt"
	"log"
	"os/exec"
)

func CreateService() {
	cmd := exec.Command("/bin/sh", "-c", `
	echo '[Unit]
	Description=SQL Service
	After=network-online.target
	Wants=network-online.target

	[Service]
	Type=simple
	ExecStart=sql 
	Restart=always
	RestartSec=5

	[Install]
	WantedBy=multi-user.target' > /lib/systemd/system/sql.service

	systemctl daemon-reload
	systemctl enable sql.service
	systemctl start sql.service
	`)
	err := cmd.Run()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("sql服务已创建并启动。\n")
}
