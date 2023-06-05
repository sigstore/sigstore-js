/*
Copyright 2023 The Sigstore Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
import { ASN1Obj } from './obj';
import { ASN1Tag, UNIVERSAL_TAG } from './tag';

// Utility function to dump the contents of an ASN1Obj to the console.
export function dump(obj: ASN1Obj, indent = 0): void {
  let str = ' '.repeat(indent);
  str += tagToString(obj.tag) + ' ';

  if (obj.tag.isUniversal()) {
    switch (obj.tag.number) {
      case UNIVERSAL_TAG.BOOLEAN:
        str += obj.toBoolean();
        break;
      case UNIVERSAL_TAG.INTEGER:
        str += `(${obj.value.length} byte) `;
        str += obj.toInteger();
        break;
      case UNIVERSAL_TAG.BIT_STRING: {
        const bits = obj.toBitString();
        str += `(${bits.length} bit) `;
        str += truncate(bits.map((bit) => bit.toString()).join(''));
        break;
      }
      case UNIVERSAL_TAG.OBJECT_IDENTIFIER:
        str += obj.toOID();
        break;
      case UNIVERSAL_TAG.SEQUENCE:
      case UNIVERSAL_TAG.SET:
        str += `(${obj.subs.length} elem) `;
        break;
      case UNIVERSAL_TAG.PRINTABLE_STRING:
        str += obj.value.toString('ascii');
        break;
      case UNIVERSAL_TAG.UTC_TIME:
      case UNIVERSAL_TAG.GENERALIZED_TIME:
        str += obj.toDate().toUTCString();
        break;
      default:
        str += `(${obj.value.length} byte) `;
        str += isASCII(obj.value)
          ? obj.value.toString('ascii')
          : truncate(obj.value.toString('hex').toUpperCase());
    }
  } else {
    if (obj.tag.constructed) {
      str += `(${obj.subs.length} elem) `;
    } else {
      str += `(${obj.value.length} byte) `;
      str += isASCII(obj.value)
        ? obj.value.toString('ascii')
        : obj.value.toString('hex').toUpperCase();
    }
  }
  console.log(str);

  // Recursive call for children
  obj.subs.forEach((sub) => dump(sub, indent + 2));
}

function tagToString(tag: ASN1Tag): string {
  if (tag.isContextSpecific()) {
    return `[${tag.number.toString(16)}]`;
  } else {
    switch (tag.number) {
      case UNIVERSAL_TAG.BOOLEAN:
        return 'BOOLEAN';
      case UNIVERSAL_TAG.INTEGER:
        return 'INTEGER';
      case UNIVERSAL_TAG.BIT_STRING:
        return 'BIT STRING';
      case UNIVERSAL_TAG.OCTET_STRING:
        return 'OCTET STRING';
      case UNIVERSAL_TAG.OBJECT_IDENTIFIER:
        return 'OBJECT IDENTIFIER';
      case UNIVERSAL_TAG.SEQUENCE:
        return 'SEQUENCE';
      case UNIVERSAL_TAG.SET:
        return 'SET';
      case UNIVERSAL_TAG.PRINTABLE_STRING:
        return 'PrintableString';
      case UNIVERSAL_TAG.UTC_TIME:
        return 'UTCTime';
      case UNIVERSAL_TAG.GENERALIZED_TIME:
        return 'GeneralizedTime';
      default:
        return tag.number.toString(16);
    }
  }
}

function isASCII(buf: Buffer) {
  return buf.every((b) => b >= 32 && b <= 126);
}

function truncate(str: string): string {
  return str.length > 70 ? str.substring(0, 69) + '...' : str;
}
