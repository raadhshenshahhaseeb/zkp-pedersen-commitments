package main

import (
	"crypto/elliptic"
	"fmt"
	"math/big"
)

func prover(generator ECPoint, blinding ECPoint, curve elliptic.Curve) {
	fx := []*big.Int{
		big.NewInt(4), // f_0
		big.NewInt(2), // f_1.x
		big.NewInt(6), // f_2.x^2
	}

	gx := []*big.Int{
		big.NewInt(3), // g_0
		big.NewInt(1), // g_1.x
		big.NewInt(7), // g_2.x^2
	}

	hx := []*big.Int{
		big.NewInt(3), // h_0
		big.NewInt(5), // h_1.x
		big.NewInt(2), // h_2.x^2
	}

	var cf []ECPoint
	for _, coeff := range fx {
		cf = append(cf, commit(coeff, generator, blinding, curve))
	}

	var cg []ECPoint
	for _, coeff := range gx {
		cg = append(cg, commit(coeff, generator, blinding, curve))
	}

	var ch []ECPoint
	for _, coeff := range hx {
		ch = append(ch, commit(coeff, generator, blinding, curve))
	}

	// random scalar u
	u := big.NewInt(10)

	pi := new(big.Int).Add(new(big.Int).Mul(u, u), u)
	pi.Add(pi, big.NewInt(1)) // pi = u^2 + u + 1

	fu := polynomialEvaluation(u, fx, blinding)
	gu := polynomialEvaluation(u, gx, blinding)
	hu := polynomialEvaluation(u, hx, blinding)

	commitmentsF := combineCommitments(cf, u, curve)
	commitmentsG := combineCommitments(cg, u, curve)
	commitmentsH := combineCommitments(ch, u, curve)

	// testing

	check(cf, blinding, generator, curve, fu)

	// testing
	verify(curve,
		generator, blinding,
		pi, fu, gu, hu,
		commitmentsF, commitmentsG, commitmentsH)
}

// this function is for testing purposes, probably will turn it into testcase
func check(points []ECPoint, blinding, generator ECPoint, curve elliptic.Curve, fu *big.Int) {
	c0 := points[0]
	c1x, c1y := curve.ScalarMult(points[1].X, points[1].Y, big.NewInt(10).Bytes())
	u2Sq := new(big.Int).Mul(big.NewInt(10), big.NewInt(10))
	c2x, c2y := curve.ScalarMult(points[2].X, points[2].Y, u2Sq.Bytes())

	t1, t2 := curve.Add(c2x, c2y, c1x, c1y)
	x, y := curve.Add(c0.X, c0.Y, t1, t2)

	piBx, piBy := curve.ScalarMult(blinding.X, blinding.Y, big.NewInt(111).Bytes())

	negXy := new(big.Int).Neg(piBy)
	_negXy := new(big.Int).Mod(negXy, curve.Params().P)

	a1, a2 := curve.Add(x, y, piBx, _negXy)

	fgx, fgy := curve.ScalarMult(generator.X, generator.Y, fu.Bytes())

	if a1.Cmp(fgx) == 0 && a2.Cmp(fgy) == 0 {
		fmt.Println("holds")
	} else {
		fmt.Println("a1: ", a1)
		fmt.Println("a2: ", a2)
		fmt.Println("fgx: ", fgx)
		fmt.Println("fgy: ", fgy)
	}
}

func polynomialEvaluation(u *big.Int, polynomial []*big.Int, blinding ECPoint) *big.Int {
	v0 := polynomial[0]
	v1 := new(big.Int).Mul(polynomial[1], u)
	v2 := new(big.Int).Mul(polynomial[2], new(big.Int).Mul(u, u))

	return new(big.Int).Add(v0, new(big.Int).Add(v1, v2))
}

func combineCommitments(commitments []ECPoint, value *big.Int, curve elliptic.Curve) ECPoint {
	if len(commitments) < 3 {
		panic("combineCommitments requires at least 3 ECPoints in the slice")
	}

	// Scalar multiplication with the first and second points
	tempCx1, tempCy1 := curve.ScalarMult(commitments[1].X, commitments[1].Y, value.Bytes())

	// Calculate value^2 once and reuse
	valueSquared := new(big.Int).Mul(value, value)
	tempCx2, tempCy2 := curve.ScalarMult(commitments[2].X, commitments[2].Y, valueSquared.Bytes())

	tempCommitmentX, tempCommitmentY := curve.Add(commitments[0].X, commitments[0].Y, tempCx1, tempCy1)
	commitmentX, commitmentY := curve.Add(tempCommitmentX, tempCommitmentY, tempCx2, tempCy2)

	// Return the new combined commitment point
	return ECPoint{
		X: commitmentX,
		Y: commitmentY,
	}
}

func commit(value *big.Int, generator, blinding ECPoint, curve elliptic.Curve) ECPoint {
	gX, gY := curve.ScalarMult(generator.X, generator.Y, value.Bytes())

	commX, commY := curve.Add(gX, gY, blinding.X, blinding.Y)

	return ECPoint{
		X: commX,
		Y: commY,
	}
}
