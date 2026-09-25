// Command server 在本地启动身份认证与令牌服务。
package main

import (
	"log"
	"net/http"

	"github.com/h3yow/identity-provider-go/internal/service"
)

func main() {
	svc := service.New(service.DefaultConfig())
	h := service.NewHTTPHandler(svc)
	addr := ":8080"
	log.Printf("identity provider listening on %s", addr)
	log.Fatal(http.ListenAndServe(addr, h.Handler()))
}
