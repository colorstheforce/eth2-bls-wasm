import "mocha";
import crypto from "crypto";
import assert from "assert";
import bls from "../";

describe("bls", () => {
  before("init", async () => {
    await bls.init(bls.BLS12_381);
  });

  it("Should sign and verify", () => {
    const msg = randomMessage();
    const sk = new bls.SecretKey();
    sk.setByCSPRNG();
    const pk = sk.getPublicKey();
    const sig = sk.sign(msg);
    assert.strictEqual(pk.verify(sig, msg), true, "invalid result");
  });
});

function getRandomBytes(size: number): Uint8Array {
  return Uint8Array.from(crypto.randomBytes(size));
}

function randomMessage(): Uint8Array {
  return getRandomBytes(32);
}
