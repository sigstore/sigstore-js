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
import { encoding as enc } from '@sigstore/core';

type JWTSubject = {
  iss: string;
  sub: string;
  email: string;
  email_verified: boolean;
};

export function extractJWTSubject(jwt: string): string {
  const parts = jwt.split('.', 3);
  const payload: JWTSubject = JSON.parse(enc.base64Decode(parts[1]));

  if (payload.email) {
    if (!payload.email_verified) {
      throw new Error('JWT email not verified by issuer');
    }
    return payload.email;
  }

  if (payload.sub) {
    return payload.sub;
  } else {
    throw new Error('JWT subject not found');
  }
}
