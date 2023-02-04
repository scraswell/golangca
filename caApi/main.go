package main

import (
	"github.com/gin-gonic/gin"
	"github.com/scraswell/golangca/authority"
	"github.com/scraswell/golangca/openssl"
	"net/http"
)

const ListRootCertificatesRoute = "/rootCerts"
const ListIntermediateCertificatesRoute = "/intCerts"

func main() {
	router := gin.Default()
	router.GET(ListRootCertificatesRoute, func(ctx *gin.Context) {
		ctx.String(
			http.StatusOK,
			openssl.ShowRootCertificateDatabase(authority.GetConfig()))
	})

	router.GET(ListIntermediateCertificatesRoute, func(ctx *gin.Context) {
		ctx.String(
			http.StatusOK,
			openssl.ShowRootCertificateDatabase(authority.GetConfig()))
	})

	router.Run()
}