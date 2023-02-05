package main

import (
	"fmt"
	"github.com/gin-contrib/gzip"
	"github.com/gin-gonic/gin"
	"github.com/scraswell/golangca/authority"
	"github.com/scraswell/golangca/openssl"
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
		args := &common.GetCertificate{
			FromRootCa:   true,
			RootCert:     true,
			SerialNumber: -1,
		}

		getCertificate(authority.GetCertificate, args, ctx)
	})

	router.GET(GetIntermediateCaCertificate, func(ctx *gin.Context) {
		args := &common.GetCertificate{
			FromRootCa:   false,
			RootCert:     true,
			SerialNumber: -1,
		}

		getCertificate(authority.GetCertificate, args, ctx)
	})

	router.GET(GetRootCertificate, func(ctx *gin.Context) {
		args := &common.GetCertificate{
			FromRootCa:   true,
			RootCert:     false,
			SerialNumber: getSerialNumber(ctx),
		}

		getCertificate(authority.GetCertificate, args, ctx)
	})

	router.GET(GetIntermediateCertificate, func(ctx *gin.Context) {
		args := &common.GetCertificate{
			FromRootCa:   false,
			RootCert:     false,
			SerialNumber: getSerialNumber(ctx),
		}

		getCertificate(authority.GetCertificate, args, ctx)
	})

	err := router.Run()
	if err != nil {
		panic(fmt.Errorf("failed to start router %w", err))
	}
}

func getSerialNumber(ctx *gin.Context) int {
	serialString := ctx.Param("serial")
	serial, err := strconv.Atoi(serialString)
	if err != nil {
		panic(fmt.Errorf("unable to cast %s to int %w", serialString, err))
	}

	return serial
}

func getCertificate(
	getCert func(certificate *common.GetCertificate) (*common.EncodedCertificate, error),
	args *common.GetCertificate,
	ctx *gin.Context) {

	cert, err := getCert(args)

	if err != nil && err.Error() == openssl.CertNotFoundError {
		ctx.AbortWithStatus(
			http.StatusNotFound)
	} else if err != nil {
		ctx.AbortWithStatus(
			http.StatusInternalServerError)
	} else {
		ctx.JSON(
			http.StatusOK,
			cert)
	}
}
