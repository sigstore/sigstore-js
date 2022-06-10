import { pae } from './dsse';

describe('pae', () => {
  const payload = Buffer.from('hello world', 'ascii');
  const payloadType = 'http://example.com/HelloWorld';

  it('generates the DSSE Pre-Authentication Encoding', () => {
    const paeBuffer = pae(payloadType, payload);

    expect(paeBuffer.toString('ascii')).toBe(
      'DSSEv1 29 http://example.com/HelloWorld 11 hello world'
    );
  });
});
