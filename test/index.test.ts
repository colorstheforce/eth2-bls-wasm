import "mocha";
import crypto from "crypto";
import assert from "assert";
import bls from "../";

describe("bls", () => {
  before("init", async () => {
    await bls.init(bls.BLS12_381);
  });

  it("verify", () => {
    const { pk, sig, msg } = getRandomData();
    assert.strictEqual(pk.verify(sig, msg), true, "invalid result");
  });

  it("aggregate signatures", () => {
    const arr = getN(4, () => getRandomData());
    const aggSig = new bls.Signature();

    aggSig.aggregate(arr.map((a) => a.sig));
  });

  it("fastAggregateVerify", () => {
    const msg = getRandomMessage();
    const arr = getN(4, () => getRandomData());
    const pks = arr.map((a) => a.pk);

    const sigs = arr.map(({ sk }) => sk.sign(msg));
    const aggSig = new bls.Signature();
    aggSig.aggregate(sigs);

    const isValid = aggSig.fastAggregateVerify(pks, msg);
    assert.strictEqual(isValid, true, "invalid result");
  });

  it("aggregateVerify", () => {
    const arr = getN(4, () => getRandomData());
    const pks = arr.map((a) => a.pk);
    const msgs = arr.map((a) => a.msg);

    const sigs = arr.map((a) => a.sig);
    const aggSig = new bls.Signature();
    aggSig.aggregate(sigs);

    const msg = Buffer.concat(msgs);
    const isValid = aggSig.aggregateVerifyNoCheck(pks, msg);
    assert.strictEqual(isValid, true, "invalid result");
  });

  it("multiVerify", () => {
    const arr = getN(4, () => getRandomData());
    const pks = arr.map((a) => a.pk);
    const msgs = arr.map((a) => a.msg);
    const sigs = arr.map((a) => a.sig);

    const isValid = bls.multiVerify(pks, sigs, msgs);
    assert.strictEqual(isValid, true, "invalid result");
  });

  describe("serialize + deserialize", () => {
    const pubkeyHex =
      "a491d1b0ecd9bb917989f0e74f0dea0422eac4a873e5e2644f368dffb9a6e20fd6e10c1b77654d067c0618f6e5a7f79a";
    const sigHex =
      "9104e74b9dfd3ad502f25d6a5ef57db0ed7d9a0e00f3500586d8ce44231212542fcfaf87840539b398bf07626705cf1105d246ca1062c6c2e1a53029a0f790ed5e3cb1f52f8234dc5144c45fc847c0cd37a92d68e7c5ba7c648a8a339f171244";

    it("pubkey", () => {
      const pk = bls.deserializeHexStrToPublicKey(pubkeyHex);
      assert.strictEqual(pk.serializeToHexStr(), pubkeyHex);
    });

    it("signature", () => {
      const sig = bls.deserializeHexStrToSignature(sigHex);
      assert.strictEqual(sig.serializeToHexStr(), sigHex);
    });
  });
});

function getRandomKeypair() {
  const sk = new bls.SecretKey();
  sk.setByCSPRNG();
  const pk = sk.getPublicKey();
  return { sk, pk };
}

function getRandomData() {
  const { sk, pk } = getRandomKeypair();
  const msg = getRandomMessage();
  const sig = sk.sign(msg);
  return { msg, sk, pk, sig };
}

function getRandomBytes(size: number): Uint8Array {
  return Uint8Array.from(crypto.randomBytes(size));
}

function getRandomMessage(): Uint8Array {
  return getRandomBytes(32);
}

function getN<T>(n: number, getter: () => T): T[] {
  return Array.from({ length: n }, () => getter());
}
