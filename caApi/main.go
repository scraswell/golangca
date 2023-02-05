package main

import (
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/scraswell/golangca/authority"
	"net/http"
)

const ListRootCertificates = "/list/root"
const ListIntermediateCertificates = "/list/int"
const GetCertificate = "/get"

func main() {
	router := gin.Default()

	router.GET(ListRootCertificates, func(ctx *gin.Context) {
		ctx.JSON(
			http.StatusOK,
			authority.ListRootCertificates())
	})

	router.GET(ListIntermediateCertificates, func(ctx *gin.Context) {
		ctx.JSON(
			http.StatusOK,
			authority.ListIntermediateCertificates())
	})

	err := router.Run()
	if err != nil {
		panic(fmt.Errorf("failed to start router %w", err))
	}
}
