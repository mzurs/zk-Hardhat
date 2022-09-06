// SPDX-License-Identifier: MIT
//// This file is MIT Licensed.
//
// Copyright 2017 Christian Reitwiessner
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
pragma solidity ^0.8.0;

library Pairing {
    struct G1Point {
        uint X;
        uint Y;
    }
    // Encoding of field elements is: X[0] * z + X[1]
    struct G2Point {
        uint[2] X;
        uint[2] Y;
    }

    /// @return the generator of G1
    function P1() internal pure returns (G1Point memory) {
        return G1Point(1, 2);
    }

    /// @return the generator of G2
    function P2() internal pure returns (G2Point memory) {
        return
            G2Point(
                [
                    10857046999023057135944570762232829481370756359578518086990519993285655852781,
                    11559732032986387107991004021392285783925812861821192530917403151452391805634
                ],
                [
                    8495653923123431417604973247489272438418190587263600148770280649306958101930,
                    4082367875863433681332203403145435568316851327593401208105741076214120093531
                ]
            );
    }

    /// @return the negation of p, i.e. p.addition(p.negate()) should be zero.
    function negate(G1Point memory p) internal pure returns (G1Point memory) {
        // The prime q in the base field F_q for G1
        uint q = 21888242871839275222246405745257275088696311157297823662689037894645226208583;
        if (p.X == 0 && p.Y == 0) return G1Point(0, 0);
        return G1Point(p.X, q - (p.Y % q));
    }

    /// @return r the sum of two points of G1
    function addition(G1Point memory p1, G1Point memory p2)
        internal
        view
        returns (G1Point memory r)
    {
        uint[4] memory input;
        input[0] = p1.X;
        input[1] = p1.Y;
        input[2] = p2.X;
        input[3] = p2.Y;
        bool success;
        assembly {
            success := staticcall(sub(gas(), 2000), 6, input, 0xc0, r, 0x60)
            // Use "invalid" to make gas estimation work
            switch success
            case 0 {
                invalid()
            }
        }
        require(success);
    }

    /// @return r the product of a point on G1 and a scalar, i.e.
    /// p == p.scalar_mul(1) and p.addition(p) == p.scalar_mul(2) for all points p.
    function scalar_mul(G1Point memory p, uint s)
        internal
        view
        returns (G1Point memory r)
    {
        uint[3] memory input;
        input[0] = p.X;
        input[1] = p.Y;
        input[2] = s;
        bool success;
        assembly {
            success := staticcall(sub(gas(), 2000), 7, input, 0x80, r, 0x60)
            // Use "invalid" to make gas estimation work
            switch success
            case 0 {
                invalid()
            }
        }
        require(success);
    }

    /// @return the result of computing the pairing check
    /// e(p1[0], p2[0]) *  .... * e(p1[n], p2[n]) == 1
    /// For example pairing([P1(), P1().negate()], [P2(), P2()]) should
    /// return true.
    function pairing(G1Point[] memory p1, G2Point[] memory p2)
        internal
        view
        returns (bool)
    {
        require(p1.length == p2.length);
        uint elements = p1.length;
        uint inputSize = elements * 6;
        uint[] memory input = new uint[](inputSize);
        for (uint i = 0; i < elements; i++) {
            input[i * 6 + 0] = p1[i].X;
            input[i * 6 + 1] = p1[i].Y;
            input[i * 6 + 2] = p2[i].X[1];
            input[i * 6 + 3] = p2[i].X[0];
            input[i * 6 + 4] = p2[i].Y[1];
            input[i * 6 + 5] = p2[i].Y[0];
        }
        uint[1] memory out;
        bool success;
        assembly {
            success := staticcall(
                sub(gas(), 2000),
                8,
                add(input, 0x20),
                mul(inputSize, 0x20),
                out,
                0x20
            )
            // Use "invalid" to make gas estimation work
            switch success
            case 0 {
                invalid()
            }
        }
        require(success);
        return out[0] != 0;
    }

    /// Convenience method for a pairing check for two pairs.
    function pairingProd2(
        G1Point memory a1,
        G2Point memory a2,
        G1Point memory b1,
        G2Point memory b2
    ) internal view returns (bool) {
        G1Point[] memory p1 = new G1Point[](2);
        G2Point[] memory p2 = new G2Point[](2);
        p1[0] = a1;
        p1[1] = b1;
        p2[0] = a2;
        p2[1] = b2;
        return pairing(p1, p2);
    }

    /// Convenience method for a pairing check for three pairs.
    function pairingProd3(
        G1Point memory a1,
        G2Point memory a2,
        G1Point memory b1,
        G2Point memory b2,
        G1Point memory c1,
        G2Point memory c2
    ) internal view returns (bool) {
        G1Point[] memory p1 = new G1Point[](3);
        G2Point[] memory p2 = new G2Point[](3);
        p1[0] = a1;
        p1[1] = b1;
        p1[2] = c1;
        p2[0] = a2;
        p2[1] = b2;
        p2[2] = c2;
        return pairing(p1, p2);
    }

    /// Convenience method for a pairing check for four pairs.
    function pairingProd4(
        G1Point memory a1,
        G2Point memory a2,
        G1Point memory b1,
        G2Point memory b2,
        G1Point memory c1,
        G2Point memory c2,
        G1Point memory d1,
        G2Point memory d2
    ) internal view returns (bool) {
        G1Point[] memory p1 = new G1Point[](4);
        G2Point[] memory p2 = new G2Point[](4);
        p1[0] = a1;
        p1[1] = b1;
        p1[2] = c1;
        p1[3] = d1;
        p2[0] = a2;
        p2[1] = b2;
        p2[2] = c2;
        p2[3] = d2;
        return pairing(p1, p2);
    }
}

contract Verifier {
    using Pairing for *;
    struct VerifyingKey {
        Pairing.G1Point alpha;
        Pairing.G2Point beta;
        Pairing.G2Point gamma;
        Pairing.G2Point delta;
        Pairing.G1Point[] gamma_abc;
    }
    struct Proof {
        Pairing.G1Point a;
        Pairing.G2Point b;
        Pairing.G1Point c;
    }

    function verifyingKey() internal pure returns (VerifyingKey memory vk) {
        vk.alpha = Pairing.G1Point(
            uint256(
                0x2899c365e191580b73f3d8924892d400267a1f8a2b1a47c5d55df30441ac0a40
            ),
            uint256(
                0x0e0c9f501defc6c8418760ae5a2d6ff82f0c066ae161eb98d51b86ce7e58bf5e
            )
        );
        vk.beta = Pairing.G2Point(
            [
                uint256(
                    0x2c1a8f89d4884a3e9c6dd92df10a47450131b18cf25ee3a12068103e78484c0b
                ),
                uint256(
                    0x2213c27ad2a72424bf9a4a3af5ee2a99251059a9f42e019e86a9509a833cd1b8
                )
            ],
            [
                uint256(
                    0x2b7491bdd30818982bfa135acc0306511a11d32d42718f697bc61f7033c6b9d0
                ),
                uint256(
                    0x249015dd539187dccd15560f1f468c3b464a07c4340aefdff3dd0a192198c40b
                )
            ]
        );
        vk.gamma = Pairing.G2Point(
            [
                uint256(
                    0x03dadaf07a92be9be680f1433d59916e4672db7f4bad3e5b85465cd6ce2c9df6
                ),
                uint256(
                    0x1256e958dce92b5f90f575258a92c2a578b893c0c74497c4a398d42bd93406b5
                )
            ],
            [
                uint256(
                    0x2f35d25e92197baac173e2805cd50b9cd1707d345e5fae069b41f4f581563d40
                ),
                uint256(
                    0x142f4e8675d32f7427e406a5a20adaeddac300bb08bca60e0ef8fb5896cd01b7
                )
            ]
        );
        vk.delta = Pairing.G2Point(
            [
                uint256(
                    0x2669f87a8b526ad99b3f8c83816b6e63907a808852abea7398c617296686d64f
                ),
                uint256(
                    0x0e4e97c573312d7b2407f59a01adcd4390d9b18b57a513e90ef79c439a91031c
                )
            ],
            [
                uint256(
                    0x1d63ab65e7d5f45d8086e9deefe16140d800879ce31ade40f73bfacb30cf813d
                ),
                uint256(
                    0x1cb701bbf03f2218d5ff677ae35930e0851fd1b6d45d8ea153519de1b267783f
                )
            ]
        );
        vk.gamma_abc = new Pairing.G1Point[](12);
        vk.gamma_abc[0] = Pairing.G1Point(
            uint256(
                0x252e283291886b1150ea30a88f3912c0c7c7437fd5c5200b057b875ebbf3862d
            ),
            uint256(
                0x1c05703fabec1926c2cf5186e0554ba7c0156271d3b92bcb2edfbe36aeee57c4
            )
        );
        vk.gamma_abc[1] = Pairing.G1Point(
            uint256(
                0x04a5c278b2c9327eff11c03bbb769d9b4e2f2687191f1b30777c0c62d9685936
            ),
            uint256(
                0x2078243f11babd421ed3f55026d425aea61441f640987d96b1c2caec291eb7c4
            )
        );
        vk.gamma_abc[2] = Pairing.G1Point(
            uint256(
                0x0a1d50f650fd2f7c8df8d5f0e62f710ab899b599bea3f5854e991ab6e851889f
            ),
            uint256(
                0x16e6f83cc67192b859da05798fbae1d2c94771733629dd26aeb8ae8354afe83b
            )
        );
        vk.gamma_abc[3] = Pairing.G1Point(
            uint256(
                0x23508857182672aff9a96bd98130da253ff6ab99e1f1a18e991f9b35e3975ec5
            ),
            uint256(
                0x1c9880eb7efbf5befd7280f71ba413f01f005f8181a22524c9b89c0bd7ea5e3c
            )
        );
        vk.gamma_abc[4] = Pairing.G1Point(
            uint256(
                0x0cdef4651e9df70783e6483a5dc9bd50c00b380de6eb190d91341083df7674ad
            ),
            uint256(
                0x0a21afcc2a692f325bc28674e427d98980055556e3165754e16545b9f68f3ee7
            )
        );
        vk.gamma_abc[5] = Pairing.G1Point(
            uint256(
                0x0ebb27f65d6350d4f39ffe6e3c051e976020c5664bc42ceada04d4bd56d6e213
            ),
            uint256(
                0x1bff0f09e6a164a75e3148c6fbd78daef0d1ad0b02a1e17a3c1f66720dcbbe39
            )
        );
        vk.gamma_abc[6] = Pairing.G1Point(
            uint256(
                0x0cd3e75391989cca5e557deeeb1be3a7b77ac0b8adf3dc5f969e73c6898470ab
            ),
            uint256(
                0x048c77540cc5b038b3c49b7fcf68928bde89eaeef7ad3d86164ba6b42e258420
            )
        );
        vk.gamma_abc[7] = Pairing.G1Point(
            uint256(
                0x3006d825e4d01195bc51b347b51811bc40bbe95105023c5d778974e5fc8dd0e9
            ),
            uint256(
                0x21a18136f7e475c6f59085733bff7ba3eb446f834f0b53c60750468e62a36bf2
            )
        );
        vk.gamma_abc[8] = Pairing.G1Point(
            uint256(
                0x29095bba254a4e88bfbdf55986d74072134815c43f899992cdcaff5ce50fb7b4
            ),
            uint256(
                0x11c55bd1fae32ae4d057472a370bbb74984e186185d877f5c7e33a7ebfdec11d
            )
        );
        vk.gamma_abc[9] = Pairing.G1Point(
            uint256(
                0x02d7e2d661b6c3efe4ea63414a6f48a20725d10c1f45140fa0d4d76a59f8842f
            ),
            uint256(
                0x025b7528eb24f9e521636e5357a9fb9f93d9c4d5d50c94e7ec7374f2b453bf6d
            )
        );
        vk.gamma_abc[10] = Pairing.G1Point(
            uint256(
                0x19377d902a917f1286f4d7477355badff23a232854b153d1673739e31bbfd8d6
            ),
            uint256(
                0x0bc68291e7ec825055365e1336e64e22ceef89f3f588592a5dc415142f5c1973
            )
        );
        vk.gamma_abc[11] = Pairing.G1Point(
            uint256(
                0x279d3d608218aca1b51b9ac73e49f80af5e822d5354a1099ddc5f6a91860718f
            ),
            uint256(
                0x23566c88b222df670eb4fe5b785aa8019fc059d6bbd482a86361c009d15d80a5
            )
        );
    }

    function verify(uint[] memory input, Proof memory proof)
        internal
        view
        returns (uint)
    {
        uint256 snark_scalar_field = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
        VerifyingKey memory vk = verifyingKey();
        require(input.length + 1 == vk.gamma_abc.length);
        // Compute the linear combination vk_x
        Pairing.G1Point memory vk_x = Pairing.G1Point(0, 0);
        for (uint i = 0; i < input.length; i++) {
            require(input[i] < snark_scalar_field);
            vk_x = Pairing.addition(
                vk_x,
                Pairing.scalar_mul(vk.gamma_abc[i + 1], input[i])
            );
        }
        vk_x = Pairing.addition(vk_x, vk.gamma_abc[0]);
        if (
            !Pairing.pairingProd4(
                proof.a,
                proof.b,
                Pairing.negate(vk_x),
                vk.gamma,
                Pairing.negate(proof.c),
                vk.delta,
                Pairing.negate(vk.alpha),
                vk.beta
            )
        ) return 1;
        return 0;
    }

    function verifyTx(Proof memory proof, uint[11] memory input)
        public
        view
        returns (bool r)
    {
        uint[] memory inputValues = new uint[](11);

        for (uint i = 0; i < input.length; i++) {
            inputValues[i] = input[i];
        }
        if (verify(inputValues, proof) == 0) {
            return true;
        } else {
            return false;
        }
    }
}
