module example.com/fixture

go 1.23.0

require (
	github.com/gin-gonic/gin v1.10.0
	golang.org/x/text v0.18.0 // indirect
	example.com/local v1.2.3
	example.com/old-fork v1.0.0
)

replace example.com/local => ../local
replace example.com/old-fork => example.com/new-fork v1.4.0
