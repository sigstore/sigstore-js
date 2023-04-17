import { sigstore } from '..';

describe('sigstore', () => {
  // This test is a bit of a hack to ensure that the types are exported
  it('exports sigstore types', async () => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const bundle: sigstore.Bundle = {} as any;
    expect(bundle).toBeDefined();

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const envelope: sigstore.Envelope = {} as any;
    expect(envelope).toBeDefined();

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const signOptions: sigstore.SignOptions = {} as any;
    expect(signOptions).toBeDefined();

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const verifyOptions: sigstore.VerifyOptions = {} as any;
    expect(verifyOptions).toBeDefined();
  });

  it('exports sigstore core functions', async () => {
    expect(sigstore.attest).toBeInstanceOf(Function);
    expect(sigstore.sign).toBeInstanceOf(Function);
    expect(sigstore.verify).toBeInstanceOf(Function);
  });

  it('exports sigstore utils', () => {
    expect(sigstore.utils).toBeDefined();
    expect(sigstore.utils.createDSSEEnvelope).toBeInstanceOf(Function);
    expect(sigstore.utils.createRekorEntry).toBeInstanceOf(Function);
  });
});
