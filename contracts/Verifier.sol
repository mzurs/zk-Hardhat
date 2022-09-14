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
    function P1() pure internal returns (G1Point memory) {
        return G1Point(1, 2);
    }
    /// @return the generator of G2
    function P2() pure internal returns (G2Point memory) {
        return G2Point(
            [10857046999023057135944570762232829481370756359578518086990519993285655852781,
             11559732032986387107991004021392285783925812861821192530917403151452391805634],
            [8495653923123431417604973247489272438418190587263600148770280649306958101930,
             4082367875863433681332203403145435568316851327593401208105741076214120093531]
        );
    }
    /// @return the negation of p, i.e. p.addition(p.negate()) should be zero.
    function negate(G1Point memory p) pure internal returns (G1Point memory) {
        // The prime q in the base field F_q for G1
        uint q = 21888242871839275222246405745257275088696311157297823662689037894645226208583;
        if (p.X == 0 && p.Y == 0)
            return G1Point(0, 0);
        return G1Point(p.X, q - (p.Y % q));
    }
    /// @return r the sum of two points of G1
    function addition(G1Point memory p1, G1Point memory p2) internal view returns (G1Point memory r) {
        uint[4] memory input;
        input[0] = p1.X;
        input[1] = p1.Y;
        input[2] = p2.X;
        input[3] = p2.Y;
        bool success;
        assembly {
            success := staticcall(sub(gas(), 2000), 6, input, 0xc0, r, 0x60)
            // Use "invalid" to make gas estimation work
            switch success case 0 { invalid() }
        }
        require(success);
    }


    /// @return r the product of a point on G1 and a scalar, i.e.
    /// p == p.scalar_mul(1) and p.addition(p) == p.scalar_mul(2) for all points p.
    function scalar_mul(G1Point memory p, uint s) internal view returns (G1Point memory r) {
        uint[3] memory input;
        input[0] = p.X;
        input[1] = p.Y;
        input[2] = s;
        bool success;
        assembly {
            success := staticcall(sub(gas(), 2000), 7, input, 0x80, r, 0x60)
            // Use "invalid" to make gas estimation work
            switch success case 0 { invalid() }
        }
        require (success);
    }
    /// @return the result of computing the pairing check
    /// e(p1[0], p2[0]) *  .... * e(p1[n], p2[n]) == 1
    /// For example pairing([P1(), P1().negate()], [P2(), P2()]) should
    /// return true.
    function pairing(G1Point[] memory p1, G2Point[] memory p2) internal view returns (bool) {
        require(p1.length == p2.length);
        uint elements = p1.length;
        uint inputSize = elements * 6;
        uint[] memory input = new uint[](inputSize);
        for (uint i = 0; i < elements; i++)
        {
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
            success := staticcall(sub(gas(), 2000), 8, add(input, 0x20), mul(inputSize, 0x20), out, 0x20)
            // Use "invalid" to make gas estimation work
            switch success case 0 { invalid() }
        }
        require(success);
        return out[0] != 0;
    }
    /// Convenience method for a pairing check for two pairs.
    function pairingProd2(G1Point memory a1, G2Point memory a2, G1Point memory b1, G2Point memory b2) internal view returns (bool) {
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
            G1Point memory a1, G2Point memory a2,
            G1Point memory b1, G2Point memory b2,
            G1Point memory c1, G2Point memory c2
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
            G1Point memory a1, G2Point memory a2,
            G1Point memory b1, G2Point memory b2,
            G1Point memory c1, G2Point memory c2,
            G1Point memory d1, G2Point memory d2
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
    function verifyingKey() pure internal returns (VerifyingKey memory vk) {
        vk.alpha = Pairing.G1Point(uint256(0x1d93738ee48c152fe870d485a31e5dea15efa6e08e02af927abc1ca1c29be877), uint256(0x14c6fed991768af8b09cce69fca16cda869f722fcaca8a17450f4c88cfde6cec));
        vk.beta = Pairing.G2Point([uint256(0x2f3f4797e953a71936caad6715257cdd98ac38cfa657a363107bee5b9f49e095), uint256(0x29186bb053d64d8398e0aee48c49619ced4683c2a0df9e08e8589835c742f3bb)], [uint256(0x1958613580dac006ea30625047c3e6ae4da2770f9e17afcaea8b0e79cfeb431e), uint256(0x06932d7a48b5f5b6205800cf8862325f4440c2885e1a762f289f460deb517c70)]);
        vk.gamma = Pairing.G2Point([uint256(0x1f30424acfaf0dcb731b2a20d824c0b6d81bc3650d68dbe98842166bb7a8f582), uint256(0x2d72e6317f060b768cc4157e42efc078caede6c05418c9a36477c9f56dfaa98d)], [uint256(0x17a3ce01bdb0f2cb3bb8c776d704d23a0e5ea4e598b99b91f40dc6298e430064), uint256(0x046be719b153f8544b34da7ab44327049e54b7accb3a5ac1f7f710a5c8fb8571)]);
        vk.delta = Pairing.G2Point([uint256(0x19f0f4b71ab152a314bb391f43612ed37b1b9a6a0f0c09b97b6824546bfc11f3), uint256(0x09f1bf6e7a9a58614e069ba0da2c4c8ddfc37b6ca7ae88d5018f9e05a991a01d)], [uint256(0x22ec7db353999d00acbdf755970ea23d5100796fbb5b1b5c9f4c16fa33fb0113), uint256(0x20e717cdc3a4e5ec8ee1b9ff8978ee5221790e48d9c97f188cd6f9c1d5eb26b1)]);
        vk.gamma_abc = new Pairing.G1Point[](12);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x175257fd9171046c765d615012b83d74e3f2b24707c2b8a1b58114d126129cc0), uint256(0x24231316e06edfc816e5ef816804ad473b6a3b5e572f7fcad97bc6accd903e82));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x29ef5eaa6fe115b510a89082a87444895ae0681030d9a35c21744a17c8e7761c), uint256(0x1b7d3faf29424ed51da2046eb285cb54e7c56510f64c7eb06fab36e45c64a0db));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x1d54898e607b540fd2f7e000783b30a366313747294f16a6a438a20c9ca41981), uint256(0x1755fcb451916b517dbe8fa0f7e5920b2eecd8e14e19b7ce9bc82311342317e2));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x03c603c7a8c201854b7061b9c8ae6b0b9d284e24bfeadec1ad7368e4587a624a), uint256(0x01cce17012e35160971af09041d1dc8a360b6a9bf8a2e946e077611079502d14));
        vk.gamma_abc[4] = Pairing.G1Point(uint256(0x1f60e8b62a66071c9c9b56643c3f64e96b5c161827b8f519ed00b6ebd7af7848), uint256(0x2f347f095783e001ab33f2e45f48888acc7e1ce865586e588e803f8dc724296e));
        vk.gamma_abc[5] = Pairing.G1Point(uint256(0x0698ea6375fb919cf1cfbeb13771dfb04c46be26660ce9fe9985186c8b3f0944), uint256(0x1d541543dacf1b90b9730d7e1f2445180eee5fcde8eec5bb1c1da2ec4beae2a2));
        vk.gamma_abc[6] = Pairing.G1Point(uint256(0x0841e39d8e27c7471ee6753bc473545e0a9dab137269ea4db4e3b107f6022f01), uint256(0x0224215f972ecf9c54284747a89cd1b72b72a1a8f3c1a42dea70a5ef4f8c69c6));
        vk.gamma_abc[7] = Pairing.G1Point(uint256(0x1bb9aed35a5c869884851adf1902c01d69b4f737b7e50f56498d099124c66962), uint256(0x2f39a3ab1ace27aaede3a734e23b13cbab90734f0f12b45cdc645cca4ca2b052));
        vk.gamma_abc[8] = Pairing.G1Point(uint256(0x2bba05ac26a0bac32819fdeaa07272bac4672568da976ee96f776f04b89b8dc8), uint256(0x11e03fcee6e66144c367a63914af50bd25009675b093758d86e900fe651d3c8b));
        vk.gamma_abc[9] = Pairing.G1Point(uint256(0x10219c6d582833da88731697bb6364063f9485168d40942dff1057e139b6df20), uint256(0x2488dc2ed1b473e62b5022fb06e07fca983bed60c4e769f99253cadcdaabdfcb));
        vk.gamma_abc[10] = Pairing.G1Point(uint256(0x00002818c056f92a0c12ad0b060d315b04336719039c6ff01fd674076e788450), uint256(0x189cb53dc155982f99524f4e7301a83725198a4452ecf29990e228984b987864));
        vk.gamma_abc[11] = Pairing.G1Point(uint256(0x256b59829d11f6c82784ae1b1ecd1ce60e9172108ca4bd722dfb676b9e7de6c7), uint256(0x2bdce0871bd6c0fe5ca1eb178f097d991df002ce606ca6ff6f5544753da95dad));
    }
    function verify(uint[] memory input, Proof memory proof) internal view returns (uint) {
        uint256 snark_scalar_field = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
        VerifyingKey memory vk = verifyingKey();
        require(input.length + 1 == vk.gamma_abc.length);
        // Compute the linear combination vk_x
        Pairing.G1Point memory vk_x = Pairing.G1Point(0, 0);
        for (uint i = 0; i < input.length; i++) {
            require(input[i] < snark_scalar_field);
            vk_x = Pairing.addition(vk_x, Pairing.scalar_mul(vk.gamma_abc[i + 1], input[i]));
        }
        vk_x = Pairing.addition(vk_x, vk.gamma_abc[0]);
        if(!Pairing.pairingProd4(
             proof.a, proof.b,
             Pairing.negate(vk_x), vk.gamma,
             Pairing.negate(proof.c), vk.delta,
             Pairing.negate(vk.alpha), vk.beta)) return 1;
        return 0;
    }
    function verifyTx(
            Proof memory proof, uint[11] memory input
        ) public view returns (bool r) {
        uint[] memory inputValues = new uint[](11);
        
        for(uint i = 0; i < input.length; i++){
            inputValues[i] = input[i];
        }
        if (verify(inputValues, proof) == 0) {
            return true;
        } else {
            return false;
        }
    }
}
