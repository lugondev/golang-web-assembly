package zk

import (
	"bytes"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/ethereum/go-ethereum/common"
	"log"
	"math/big"
)

type GnarkGroth16 struct {
	// groth16 gnark objects
	vk      groth16.VerifyingKey
	pk      groth16.ProvingKey
	circuit Circuit
	r1cs    frontend.CompiledConstraintSystem
}

func NewGnarkGroth16() *GnarkGroth16 {
	g16 := &GnarkGroth16{}
	g16.setup()
	return g16
}

type Proof struct {
	A     [2]*big.Int    `json:"a"`
	B     [2][2]*big.Int `json:"b"`
	C     [2]*big.Int    `json:"c"`
	Input [1]*big.Int    `json:"input"`
}

func (t *GnarkGroth16) setup() {

	var err error
	t.r1cs, err = frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &t.circuit)
	if err != nil {
		log.Fatal(err, "compiling R1CS failed")
	}
	pkContent := "00000000000000010000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000005135b52945a13d9aa49b9b57c33cd568ba9ae5ce9ca4a2d06e7f3fbd4c666666707c6234b680a53b79d6109cfeb160ed1d87ddf715bc2f5112b3735dafa22ba39178ad4ac0d4b734c97b181940b8232b86bc9904ca8aad205ce141e118aa98ec12fb32558f7900e22d97549efa38c7b92d0b595e9facd1697b560c16310558b3902a4aa6db7d32c41ffdace4c64c61c0177508762809aa97662d5f820ba39baf2253559084353ef60cd3547a438c92fc98510886ba57a969939105c6db6f8de301fb00c039509f3a77f53da2f44946c415290311bb3f9f56ff23083273770ec1100000001000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000020000000100000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000002000000012de14ae61dc856d09528737f4e7c31eca87b6daae097c208cf7c34f92acdcc331f34439428b32479adcc0e79a9d425d4be670db4da53c5453e51ff13a557d45c0000000100c5dfd53edeca595df92d335bd94f151c928bb7cda94d023447570972c965e612988160161831d32cc96fb2a0af51ded561fb3a273c51be9a28d0cd43eb812900bb62f09364661a0da860a246c00d17cca2be69b1c0d2f9df672046671a4d27187ed683b24f68ec9647d9a73d549f318a4abe2576a9a8896b077a95bfe3b8aa14ca8e69adef6a35c6fbbf3f6de01bc14a369674c41c00e247bc99a6d0c07b5c2c76e3ce676f6c3f870311822febe32a25562977681a48ec2ff9d3c8058739c4056ea8263f9c0ff9a70a184fc21b25dbe18f04cacb4b0351062ec3639c8b9b960cb1aaaaedae12a427f1887ef618a4f49a7a952ca141210b8776e91b9fdf3afb16e1b8e54de33af405ba5e638f6b85c457a2df97c391c87c5e1f4c16575d3a82060ea8cdb56213555019103ea7f60ebad70ba5e38aa1327366f78b9c300edba000000001198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c21800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa000000000000000300000000000000020000000000000002000101010001"
	vkContent := "07c6234b680a53b79d6109cfeb160ed1d87ddf715bc2f5112b3735dafa22ba39178ad4ac0d4b734c97b181940b8232b86bc9904ca8aad205ce141e118aa98ec12fb32558f7900e22d97549efa38c7b92d0b595e9facd1697b560c16310558b3902a4aa6db7d32c41ffdace4c64c61c0177508762809aa97662d5f820ba39baf200bb62f09364661a0da860a246c00d17cca2be69b1c0d2f9df672046671a4d27187ed683b24f68ec9647d9a73d549f318a4abe2576a9a8896b077a95bfe3b8aa14ca8e69adef6a35c6fbbf3f6de01bc14a369674c41c00e247bc99a6d0c07b5c2c76e3ce676f6c3f870311822febe32a25562977681a48ec2ff9d3c8058739c4091d7f405032c818f108db54143a6ccbb4d4c00c98ce61f36dc7073e92241a40087004f53ac5ec0638b904ae38f83406fb152fff698b62eaaddbe198273f80c1296b5a74b7bf0c867b3148b7990e9cfe8f413adad33c8d095b4d60b8cc090f2123e72264d585f76dca77e51da44b999c12ea76023845f1e6445c396d9014c49b253559084353ef60cd3547a438c92fc98510886ba57a969939105c6db6f8de301fb00c039509f3a77f53da2f44946c415290311bb3f9f56ff23083273770ec11056ea8263f9c0ff9a70a184fc21b25dbe18f04cacb4b0351062ec3639c8b9b960cb1aaaaedae12a427f1887ef618a4f49a7a952ca141210b8776e91b9fdf3afb16e1b8e54de33af405ba5e638f6b85c457a2df97c391c87c5e1f4c16575d3a82060ea8cdb56213555019103ea7f60ebad70ba5e38aa1327366f78b9c300edba000000002294c8f4bf3e17a21316672a288a64d52a171af8d5b1d303637edd494809c11230763e66ccfa58ec46b2b43f8b46121cf9d4741ceadcea7be0e3e3188c2fbe21d0c1a45fe52a4fb5ef233a5c3edb3e8df54c4b905aee721c85c0c643d885429f5205652091514ac8fbb389bb44b0613e448793f75420b3f44fed7608c34928412"
	// read proving and verifying keys
	t.pk = groth16.NewProvingKey(ecc.BN254)
	{
		pkBuf := bytes.NewBuffer(common.FromHex(pkContent))
		_, err = t.pk.ReadFrom(pkBuf)
		if err != nil {
			log.Fatal(err, "reading proving key failed")
		}
	}
	t.vk = groth16.NewVerifyingKey(ecc.BN254)
	{
		vkBuf := bytes.NewBuffer(common.FromHex(vkContent))
		_, err = t.vk.ReadFrom(vkBuf)
		if err != nil {
			log.Fatal(err, "reading verifying key failed")
		}
	}

}

func (t *GnarkGroth16) VerifyProof() Proof {
	// create a valid proof
	var assignment Circuit
	assignment.X = 3
	assignment.Y = 35

	// witness creation
	witness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	if err != nil {
		return Proof{}
	}

	// prove
	proof, err := groth16.Prove(t.r1cs, t.pk, witness)
	if err != nil {
		return Proof{}
	}

	// ensure gnark (Go) code verifies it
	publicWitness, _ := witness.Public()

	err = groth16.Verify(proof, t.vk, publicWitness)
	if err != nil {
		return Proof{}
	}

	// get proof bytes
	const fpSize = 4 * 8
	var buf bytes.Buffer
	_, err = proof.WriteRawTo(&buf)
	if err != nil {
		return Proof{}
	}
	proofBytes := buf.Bytes()

	// solidity contract inputs
	proofStruct := Proof{}
	// proof.Ar, proof.Bs, proof.Krs
	proofStruct.A[0] = new(big.Int).SetBytes(proofBytes[fpSize*0 : fpSize*1])
	proofStruct.A[1] = new(big.Int).SetBytes(proofBytes[fpSize*1 : fpSize*2])
	proofStruct.B[0][0] = new(big.Int).SetBytes(proofBytes[fpSize*2 : fpSize*3])
	proofStruct.B[0][1] = new(big.Int).SetBytes(proofBytes[fpSize*3 : fpSize*4])
	proofStruct.B[1][0] = new(big.Int).SetBytes(proofBytes[fpSize*4 : fpSize*5])
	proofStruct.B[1][1] = new(big.Int).SetBytes(proofBytes[fpSize*5 : fpSize*6])
	proofStruct.C[0] = new(big.Int).SetBytes(proofBytes[fpSize*6 : fpSize*7])
	proofStruct.C[1] = new(big.Int).SetBytes(proofBytes[fpSize*7 : fpSize*8])
	//fmt.Println("a", proofStruct.A)
	//fmt.Println("b", proofStruct.B)
	//fmt.Println("c", proofStruct.C)

	// public witness
	proofStruct.Input[0] = new(big.Int).SetUint64(35)

	return proofStruct
}
