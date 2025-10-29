package main

import(
	"context"
	"fmt"
	"time"

	"github.com/Fleonex-dev/Options/options-kite/kite-auth/internal/kiteauth"
)

func main() {
	c := kiteauth.New()
	u, _ := kiteauth.BuildLoginURL("demo_key","")
	fmt.Println("loging url:",u)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = ctx
	_ = c
}