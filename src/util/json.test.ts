import { canonicalize } from './json';

describe('canonicalize', () => {
  // Test data from https://github.com/cyberphone/json-canonicalization/tree/master/testdata
  const input = [
    // array
    [56, { d: true, '10': null, '1': [] }],
    // non-ascii keys
    {
      peach: 'This sorting order',
      péché: 'is wrong according to French',
      pêche: 'but canonicalization MUST',
      sin: 'ignore locale',
    },
    // structure
    {
      '1': { f: { f: 'hi', F: 5 }, '\n': 56.0 },
      '10': {},
      '': 'empty',
      a: {},
      '111': [{ e: 'yes', E: 'no' }],
      A: {},
    },
    // unicode
    {
      'Unnormalized Unicode': 'A\u030a',
    },
    // values
    {
      numbers: [
        333333333.33333329, 1e30, 4.5, 2e-3, 0.000000000000000000000000001,
      ],
      string: '\u20ac$\u000F\u000aA\'\u0042\u0022\u005c\\"/',
      literals: [null, true, false],
    },
    // weird
    {
      '\u20ac': 'Euro Sign',
      '\r': 'Carriage Return',
      '\u000a': 'Newline',
      '1': 'One',
      '\u0080': 'Control\u007f',
      '\ud83d\ude02': 'Smiley',
      '\u00f6': 'Latin Small Letter O With Diaeresis',
      '\ufb33': 'Hebrew Letter Dalet With Dagesh',
      '</script>': 'Browser Challenge',
    },
  ];

  const output = [
    '[56,{"1":[],"10":null,"d":true}]',
    '{"peach":"This sorting order","péché":"is wrong according to French","pêche":"but canonicalization MUST","sin":"ignore locale"}',
    '{"":"empty","1":{"\\n":56,"f":{"F":5,"f":"hi"}},"10":{},"111":[{"E":"no","e":"yes"}],"A":{},"a":{}}',
    '{"Unnormalized Unicode":"Å"}',
    `{"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],"string":"€$\\u000f\\nA'B\\"\\\\\\\\\\"/"}`,
    '{"\\n":"Newline","\\r":"Carriage Return","1":"One","</script>":"Browser Challenge","":"Control","ö":"Latin Small Letter O With Diaeresis","€":"Euro Sign","😂":"Smiley","דּ":"Hebrew Letter Dalet With Dagesh"}',
  ];

  it('returns the proper canonicalized object', () => {
    input.forEach((_, i) => {
      expect(canonicalize(input[i])).toEqual(output[i]);
    });
  });
});
