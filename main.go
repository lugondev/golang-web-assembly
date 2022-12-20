package main

import (
	"encoding/json"
	"fmt"
	"golang-wasm-example/zk"
	"syscall/js"
)

func prettyJson(input string) (string, error) {
	var raw any
	if err := json.Unmarshal([]byte(input), &raw); err != nil {
		return "", err
	}
	pretty, err := json.MarshalIndent(raw, "", "  ")
	if err != nil {
		return "", err
	}
	return string(pretty), nil
}

func jsonWrapper() js.Func {
	jsonFunc := js.FuncOf(func(this js.Value, args []js.Value) any {
		if len(args) != 1 {
			return "Invalid no of arguments passed"
		}
		inputJSON := args[0].String()
		fmt.Printf("input %s\n", inputJSON)
		pretty, err := prettyJson(inputJSON)
		if err != nil {
			fmt.Printf("unable to convert to json %s\n", err)
			return err.Error()
		}
		return pretty
	})
	return jsonFunc
}

func proof() js.Func {
	jsonFunc := js.FuncOf(func(this js.Value, args []js.Value) any {
		//if len(args) != 0 {
		//	return "No arguments required"
		//}
		g16 := zk.NewGnarkGroth16()
		proofGenerated := g16.VerifyProof()
		//proofMap := make(map[string]interface{})
		//proofMap["a"] = proofGenerated.A
		//proofMap["b"] = proofGenerated.B
		//proofMap["c"] = proofGenerated.C
		//proofMap["input"] = proofGenerated.Input
		proofJSON, _ := json.Marshal(proofGenerated)
		fmt.Println("proofJSON", string(proofJSON))

		return string(proofJSON)
	})
	return jsonFunc
}

func main() {
	fmt.Println("Go Web Assembly")
	js.Global().Set("formatJSON", jsonWrapper())
	js.Global().Set("generateProof", proof())
	<-make(chan bool)
}
