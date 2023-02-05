package main

import (
	"fmt"
	"github.com/gin-contrib/gzip"
	"github.com/gin-gonic/gin"
	"github.com/scraswell/golangca/authority"
	"github.com/scraswell/golangca/openssl/common"
	"net/http"
	"strconv"
)

const ListRootCertificates = "/list/root"
const ListIntermediateCertificates = "/list/int"
const GetRootCaCertificate = "/get/root"
const GetIntermediateCaCertificate = "/get/int"
const GetRootCertificate = "/get/root/:serial"
const GetIntermediateCertificate = "/get/int/:serial"

func main() {
	router := gin.Default()
	router.Use(gzip.Gzip(gzip.DefaultCompression))

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

	router.GET(GetRootCaCertificate, func(ctx *gin.Context) {
		ctx.JSON(
			http.StatusOK,
			authority.GetRootCaCertificate())
	})

	router.GET(GetIntermediateCaCertificate, func(ctx *gin.Context) {
		ctx.JSON(
			http.StatusOK,
			authority.GetIntermediateCaCertificate())
	})

	router.GET(GetRootCertificate, func(ctx *gin.Context) {
		serialString := ctx.Param("serial")
		serial, err := strconv.Atoi(serialString)
		if err != nil {
			panic(fmt.Errorf("unable to cast %s to int %w", serialString, err))
		}

		ctx.JSON(
			http.StatusOK,
			authority.GetCertificate(&common.GetCertificate{
				FromRootCa:   true,
				RootCert:     false,
				SerialNumber: serial,
			}))
	})

	router.GET(GetIntermediateCertificate, func(ctx *gin.Context) {
		serial := ctx.GetInt("serial")

		ctx.JSON(
			http.StatusOK,
			authority.GetCertificate(&common.GetCertificate{
				FromRootCa:   false,
				RootCert:     false,
				SerialNumber: serial,
			}))
	})

	err := router.Run()
	if err != nil {
		panic(fmt.Errorf("failed to start router %w", err))
	}
}
