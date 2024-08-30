package main

import (
	"crypto/elliptic"
	"fmt"
	"math/big"
)

func verify(curve elliptic.Curve,
	generator, blinding ECPoint,
	pi, fu, gu, hu *big.Int,
	commitmentsF, commitmentsG, commitmentsH ECPoint) bool {

	piBx, piBy := curve.ScalarMult(blinding.X, blinding.Y, pi.Bytes())

	negXy := new(big.Int).Neg(piBy)
	_negXy := new(big.Int).Mod(negXy, curve.Params().P)

	holds := evaluate(curve, ECPoint{X: piBx, Y: _negXy}, commitmentsF, fu, generator) &&
		evaluate(curve, ECPoint{X: piBx, Y: _negXy}, commitmentsG, gu, generator) &&
		evaluate(curve, ECPoint{X: piBx, Y: _negXy}, commitmentsH, hu, generator)

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
