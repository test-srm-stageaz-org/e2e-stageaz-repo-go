module github.com/test/vulnerable-go-app

go 1.19

require (

	// Authentication & JWT
	github.com/dgrijalva/jwt-go v3.2.0+incompatible // CVE-2020-26160: JWT validation bypass
	// Web Frameworks & HTTP
	github.com/gin-gonic/gin v1.7.0 // CVE-2020-28483: Path traversal

	// Database Drivers
	github.com/lib/pq v1.0.0 // PostgreSQL driver

	// Data Serialization
	gopkg.in/yaml.v2 v2.2.8 // CVE-2019-11254: Denial of Service
)

require (
	github.com/gin-contrib/sse v0.1.0 // indirect
	github.com/go-playground/locales v0.13.0 // indirect
	github.com/go-playground/universal-translator v0.17.0 // indirect
	github.com/go-playground/validator/v10 v10.4.1 // indirect
	github.com/golang/protobuf v1.3.3 // indirect; CVE-2021-3121: DoS vulnerability
	github.com/json-iterator/go v1.1.9 // indirect
	github.com/kr/text v0.2.0 // indirect
	github.com/leodido/go-urn v1.2.0 // indirect
	github.com/mattn/go-isatty v0.0.12 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.1 // indirect
	github.com/niemeyer/pretty v0.0.0-20200227124842-a10e7caefd8e // indirect
	github.com/stretchr/testify v1.5.1 // indirect
	github.com/ugorji/go/codec v1.1.7 // indirect; CVE-2020-5625: Improper input validation

	// Cryptography
	golang.org/x/crypto v0.0.0-20200622213623-75b288015ac9 // indirect; Multiple CVEs
	golang.org/x/sys v0.0.0-20200909081042-eff7692f9009 // indirect
	gopkg.in/check.v1 v1.0.0-20200227125254-8fa46927fb4f // indirect
)
