# Resources
## https://github.com/omeid/go-resources
```
go install github.com/omeid/go-resources/cmd/resources@latest

FROM ./config

~/go/bin/resources -declare -var=FS -package=openssl_assets -output=../openssl_assets/main.go int_ca-openssl.conf.j2 root_ca-openssl.conf.j2
```
