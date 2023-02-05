package main

import (
	"github.com/gin-gonic/gin"
	"github.com/scraswell/golangca/authority"
	"net/http"
)

const ListRootCertificatesRoute = "/rootCerts"
const ListIntermediateCertificatesRoute = "/intCerts"

func main() {
	router := gin.Default()
	router.GET(ListRootCertificatesRoute, func(ctx *gin.Context) {
		ctx.JSON(
			http.StatusOK,
			authority.ListRootCertificates())
	})

	router.GET(ListIntermediateCertificatesRoute, func(ctx *gin.Context) {
		ctx.JSON(
			http.StatusOK,
			authority.ListIntermediateCertificates())
	})

	router.Run()
}
