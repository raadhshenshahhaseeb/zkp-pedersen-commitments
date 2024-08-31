package main

import (
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"
)

func challenge(curve elliptic.Curve, hashes [][]byte) *big.Int {
	hasher := sha256.New()

	// Concatenate all hashes into a single hash
	for _, hash := range hashes {
		hasher.Write(hash) // Directly write each hash to the hasher
	}

	// Compute the final hash value
	finalHash := hasher.Sum(nil)

	// Generate a random big.Int in the range [0, P-1]
	blindingScalar, err := rand.Int(rand.Reader, curve.Params().P)
	if err != nil {
		return nil
	}

	// Convert the final hash to a big.Int
	hashPart := new(big.Int).SetBytes(finalHash)

	// Combine the hashPart and the randomPart by adding them
	u := new(big.Int).Add(hashPart, blindingScalar)

	// Reduce u mod P to ensure it is within the field F_P
	u.Mod(u, curve.Params().P)

	return u
}

func verify(curve elliptic.Curve,
	generator, blinding ECPoint,
	pi, fu, gu, hu *big.Int,
	commitments ECPoint) bool {

	piBx, piBy := curve.ScalarMult(blinding.X, blinding.Y, pi.Bytes())

	negXy := new(big.Int).Neg(piBy)
	_negXy := new(big.Int).Mod(negXy, curve.Params().P)

	holds := evaluate(curve, ECPoint{X: piBx, Y: _negXy}, commitments, fu, generator)

	if !holds {
		fmt.Println("commitments not held")
		return false
	}

	return holds
}

func evaluate(curve elliptic.Curve,
	point, commitment ECPoint,
	evaluatedPoly *big.Int, generator ECPoint) bool {

	lhsX, lhsY := curve.Add(commitment.X, commitment.Y, point.X, point.Y)
	rhsX, rhsY := curve.ScalarMult(generator.X, generator.Y, evaluatedPoly.Bytes())

	if rhsX.Cmp(lhsX) == 0 && rhsY.Cmp(lhsY) == 0 {
		fmt.Println("LHS")
		fmt.Println("lhsX: ", lhsX.String())
		fmt.Println("lhsY: ", lhsY.String())
		fmt.Println("\nRHS")
		fmt.Println("rhsX: ", rhsX.String())
		fmt.Println("rhsY: ", rhsY.String())
		fmt.Println("matched")
		return true
	} else {
		fmt.Println("LHS")
		fmt.Println("lhsX: ", lhsX.String())
		fmt.Println("lhsY: ", lhsY.String())
		fmt.Println("\nRHS")
		fmt.Println("rhsX: ", rhsX.String())
		fmt.Println("rhsY: ", rhsY.String())
	}

	return false
}
