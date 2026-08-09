// Test vector 1 from BIP-32, published in the specification.
const SEED = '000102030405060708090a0b0c0d0e0f';
const XPRV = 'xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi';

describe('bip32', () => {
  it('derives the master key from the published vector', () => {
    expect(deriveMaster(SEED)).toBe(XPRV);
  });
});
