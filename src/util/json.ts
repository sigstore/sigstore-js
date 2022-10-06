// JSON canonicalization per https://github.com/cyberphone/json-canonicalization
export function canonicalize(object: any): string {
  let buffer = '';

  if (object === null || typeof object !== 'object' || object.toJSON != null) {
    // Primitives or toJSONable objects
    buffer += JSON.stringify(object);
  } else if (Array.isArray(object)) {
    // Array - maintain element order
    buffer += '[';
    let first = true;
    object.forEach((element) => {
      if (!first) {
        buffer += ',';
      }
      first = false;
      // recursive call
      buffer += canonicalize(element);
    });
    buffer += ']';
  } else {
    // Object - Sort properties before serializing
    buffer += '{';
    let first = true;
    Object.keys(object)
      .sort()
      .forEach((property) => {
        if (!first) {
          buffer += ',';
        }
        first = false;
        buffer += JSON.stringify(property);
        buffer += ':';
        // recursive call
        buffer += canonicalize(object[property]);
      });
    buffer += '}';
  }

  return buffer;
}
