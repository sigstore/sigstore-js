/*
Copyright 2022 The Sigstore Authors.

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
// https://dev.to/maxime1992/implement-a-generic-oneof-type-with-typescript-22em

// Returns a type that is the union of all value types in the given object.
type ValueOf<Obj> = Obj[keyof Obj];

// Returns a type narrowing the given object to only the given key -- all
// other keys must be undefined.
type OneOnly<Obj, K extends keyof Obj> = {
  [key in Exclude<keyof Obj, K>]: undefined;
} & { [key in K]: Obj[K] };

// Returns a type that is the union of all OneOnly types for the given object.
// This type is not actually usable as no value could ever satisfy it.
type OneOfByKey<Obj> = { [key in keyof Obj]: OneOnly<Obj, key> };

// Returns a type that is the union of all OneOnly types for the given object.
export type OneOf<T> = ValueOf<OneOfByKey<T>>;
