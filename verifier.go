package main

import (
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"
)

func challenge(curve elliptic.Curve, hashedCommitment []byte) *big.Int {
	hasher := sha256.New()

	hasher.Write(hashedCommitment)

	finalHash := hasher.Sum(nil)

	blindingScalar, err := rand.Int(rand.Reader, curve.Params().P)
	if err != nil {
		return nil
	}

	hashPart := new(big.Int).SetBytes(finalHash)

	u := new(big.Int).Add(hashPart, blindingScalar)

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
