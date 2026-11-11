// RevLens fixture: a Go service binary that links protoc-gen-go code for revdemo.proto and
// embeds an OpenAPI document and a GraphQL schema, the way real services ship them.
package main

import (
	_ "embed"
	"fmt"

	gen "example.com/revdemo/gen"
	"google.golang.org/protobuf/proto"
)

//go:embed openapi.yaml
var openapiYAML string

//go:embed schema.graphql
var schemaSDL string

const getUserQuery = `query GetUser($id: ID!) { user(id: $id) { id email role } }`

func main() {
	u := &gen.User{Id: "u1", Email: "a@example.com", Role: gen.Role_ROLE_ADMIN}
	b, _ := proto.Marshal(u)
	fmt.Println(len(b), len(openapiYAML), len(schemaSDL), len(getUserQuery))
}
