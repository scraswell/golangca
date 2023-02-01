# OpenSSL Resources
## https://github.com/omeid/go-resources
Creates embedded resources.

### From the root of the repository
```
pushd openssl/assets
go install github.com/omeid/go-resources/cmd/resources@latest
~/go/bin/resources -declare -var=FS -package=assets -output=./assets.go resources/int_ca-openssl.conf.j2 resources/root_ca-openssl.conf.j2
popd
```
