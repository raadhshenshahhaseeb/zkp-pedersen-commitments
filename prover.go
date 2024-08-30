package main

import (
	"crypto/elliptic"
	"math/big"
)

func prover(g ECPoint, blinding ECPoint, curve elliptic.Curve) {
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
	for i, coeff := range fx {
		if i == 2 {
			sqr := new(big.Int).Mul(coeff, coeff)
			// fmt.Printf("Coefficient of x^%d after square: %v\n", j, sqr)
			cf = append(cf, commit(sqr, g, blinding, curve))
		} else {
			// fmt.Printf("Coefficient of x^%d: %s\n", j, coeff.String())
			cf = append(cf, commit(coeff, g, blinding, curve))
		}
	}

	var cg []ECPoint
	for i, coeff := range gx {
		if i == 2 {
			sqr := new(big.Int).Mul(coeff, coeff)
			// fmt.Printf("Coefficient of x^%d after square: %v\n", j, sqr)
			cg = append(cg, commit(sqr, g, blinding, curve))
		} else {
			// fmt.Printf("Coefficient of x^%d: %s\n", j, coeff.String())
			cg = append(cg, commit(coeff, g, blinding, curve))
		}
	}

	var ch []ECPoint
	for i, coeff := range hx {
		if i == 2 {
			sqr := new(big.Int).Mul(coeff, coeff)
			// fmt.Printf("Coefficient of x^%d after square: %v\n", j, sqr)
			ch = append(ch, commit(sqr, g, blinding, curve))
		} else {
			// fmt.Printf("Coefficient of x^%d: %s\n", j, coeff.String())
			ch = append(ch, commit(coeff, g, blinding, curve))
		}
	}

	u := getScalarFromVerifier()
	pi := new(big.Int).Add(new(big.Int).Mul(u, u), u)

	fu := polynomialEvaluation(u, fx, blinding)
	gu := polynomialEvaluation(u, gx, blinding)
	hu := polynomialEvaluation(u, hx, blinding)

	commitmentsF := combineCommitments(cf, u, curve)
	commitmentsG := combineCommitments(cg, u, curve)
	commitmentsH := combineCommitments(ch, u, curve)

	verify(curve,
		g, blinding,
		pi, fu, gu, hu,
		*commitmentsF, *commitmentsG, *commitmentsH)
}

func polynomialEvaluation(u *big.Int, polynomial []*big.Int, blinding ECPoint) *big.Int {
	v0 := polynomial[0]
	v1 := new(big.Int).Mul(polynomial[1], u)
	v2 := new(big.Int).Mul(polynomial[2], new(big.Int).Mul(u, u))

	return new(big.Int).Add(v0, new(big.Int).Add(v1, v2))
}

// combineCommitments combines multiple elliptic curve points with a scalar value to produce a new commitment.
// The commitments slice should contain at least 3 ECPoints.
func combineCommitments(commitments []ECPoint, value *big.Int, curve elliptic.Curve) *ECPoint {
	// Ensure the slice contains at least 3 points
	if len(commitments) < 3 {
		panic("combineCommitments requires at least 3 ECPoints in the slice")
	}

	// Scalar multiplication with the first and second points
	tempCx1, tempCy1 := curve.ScalarMult(commitments[1].X, commitments[1].Y, value.Bytes())

	// Calculate value^2 once and reuse
	valueSquared := new(big.Int).Mul(value, value)
	tempCx2, tempCy2 := curve.ScalarMult(commitments[2].X, commitments[2].Y, valueSquared.Bytes())

	// Add the results to the first commitment
	tempCommitmentX, tempCommitmentY := curve.Add(commitments[0].X, commitments[0].Y, tempCx1, tempCy1)
	commitmentX, commitmentY := curve.Add(tempCommitmentX, tempCommitmentY, tempCx2, tempCy2)

	// Return the new combined commitment point
	return &ECPoint{
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
