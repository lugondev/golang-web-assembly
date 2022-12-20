package zk

import "github.com/consensys/gnark/frontend"

type Circuit struct {
	X frontend.Variable `gnark:"x"`
	Y frontend.Variable `gnark:",public"`
}

func (circuit *Circuit) Define(api frontend.API) error {
	x3 := api.Mul(circuit.X, 10)
	api.AssertIsEqual(circuit.Y, api.Add(x3, 5))

	return nil
}
