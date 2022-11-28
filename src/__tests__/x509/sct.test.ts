import { SignedCertificateTimestamp } from '../../x509/sct';

describe('SignedCertificateTimestamp', () => {
  const x = Buffer.from(
    '00086092f02852ff6845d1d16b27849c456718ac163dc338d26de6bc2206366f72000001836182f22d0000040300463044022051c3498ff13c7d6cdbc4f973fa1dd299b9ca59d432726f9ddc35509b7978d8060220455a6062ad64fdc24902fbfdb56c216b778d7f5b700ee7253e33ffa061ea72b9',
    'hex'
  );
  describe('parsing', () => {
    it('foo', () => {
      const sct = SignedCertificateTimestamp.parseBuffer(x);
      expect(sct.timestamp.toISOString()).toEqual('2022-09-21T19:25:15.181Z');
    });
  });
});
