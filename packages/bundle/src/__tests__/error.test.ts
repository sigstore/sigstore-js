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
import { ValidationError } from '../error';

describe('ValidationError', () => {
  describe('constructor', () => {
    const error = new ValidationError('message', ['field1', 'field2']);

    it('sets the message', () => {
      expect(error.message).toBe('message');
    });

    it('sets the fields', () => {
      expect(error.fields).toEqual(['field1', 'field2']);
    });
  });
});
