import { BIish, toJSBI } from "@ckb-lumos/bi";
import { bytes, BytesLike } from "@ckb-lumos/codec";
import { TypedData, getStructHash, getTypeHash } from "eip-712";
import { top_level } from "./schema";
import { isEqual } from "lodash";
import JSBI from "jsbi";

export * as schema from "./schema";

export type RefCell = {
  type: "RefCell";
  value: {
    source: BIish;
    index: number;
    offset: number;
  };
};

export type RefTransaction = {
  type: "RefTransaction";
  value: {
    offset: number;
  };
};

export type Byte32 = {
  type: "Byte32";
  value: Uint8Array;
};

export type Hash = Byte32 | RefCell | RefTransaction;

export interface HashGenerator {
  domain_separator: (data: TypedData) => Hash;
  type_hash: (data: TypedData, type: string) => Hash;
}

export const DEFAULT_HASH_GENERATOR = {
  domain_separator: (data: TypedData): Hash => ({
    type: "Byte32",
    value: getStructHash(data, "EIP712Domain", data.domain),
  }),
  type_hash: (data: TypedData, type: string): Hash => ({
    type: "Byte32",
    value: getTypeHash(data, type),
  }),
};

export function buildTypedMessage(
  data: TypedData,
  hasher: HashGenerator = DEFAULT_HASH_GENERATOR,
): Record<string, any> {
  const table = {
    domain_separator: hasher.domain_separator(data),
    message: buildStruct(data, hasher, data.message, data.primaryType),
  };
  return {
    type: "EIP712",
    value: table,
  };
}

export function serializeTypedMessage(
  data: TypedData,
  hasher: HashGenerator = DEFAULT_HASH_GENERATOR,
): Uint8Array {
  return top_level.TypedMessage.pack(buildTypedMessage(data, hasher));
}

export function parseTypedMessage(
  data: TypedData,
  packed: Record<string, any> | Uint8Array,
  hasher: HashGenerator = DEFAULT_HASH_GENERATOR,
): TypedData {
  let unpacked: Record<string, any>;
  if (ArrayBuffer.isView(packed)) {
    unpacked = top_level.TypedMessage.unpack(packed);
  } else {
    unpacked = packed;
  }
  if (unpacked.type != "EIP712") {
    throw new Error(
      `Expected EIP712 union typed message, but found ${unpacked.type}`,
    );
  }
  const message = unpacked.value;
  const expectedDomainSeparator = hasher.domain_separator(data);
  if (
    expectedDomainSeparator.type === "Byte32" &&
    message.domain_separator.type === "Byte32"
  ) {
    if (
      !isEqual(
        expectedDomainSeparator.value,
        bytes.bytify(message.domain_separator.value),
      )
    ) {
      throw new Error(
        `Expected domain separator: ${
          expectedDomainSeparator.value
        }, actual domain separator: ${bytes.bytify(
          message.domain_separator.value,
        )}`,
      );
    }
  }

  const parsedMessage = parseStruct(
    data,
    hasher,
    message.message,
    data.primaryType,
  );

  return Object.assign({}, data, { message: parsedMessage });
}

export function buildSighashWithActionWitness(
  data: TypedData,
  lock: BytesLike,
  hasher: HashGenerator = DEFAULT_HASH_GENERATOR,
): Record<string, any> {
  return {
    type: "SighashWithAction",
    value: {
      message: buildTypedMessage(data, hasher),
      lock: bytes.bytify(lock),
    },
  };
}

export function serializeSighashWithActionWitness(
  data: TypedData,
  lock: BytesLike,
  hasher: HashGenerator = DEFAULT_HASH_GENERATOR,
): Uint8Array {
  return top_level.ExtendedWitness.pack(
    buildSighashWithActionWitness(data, lock, hasher),
  );
}

export function parseSighashWithActionWitness(
  data: TypedData,
  witness: BytesLike,
  hasher: HashGenerator = DEFAULT_HASH_GENERATOR,
): [TypedData, Uint8Array] {
  let unpacked = top_level.ExtendedWitness.unpack(witness);
  if (unpacked.type != "SighashWithAction") {
    throw new Error("Passed witness is not SighashWithAction!");
  }
  const { lock, message } = unpacked.value;

  let typedData = parseTypedMessage(data, message, hasher);
  return [typedData, bytes.bytify(lock)];
}

type Struct = {
  type_hash: Hash;
  values: any[];
};
type Value = {
  type: string;
  value: any;
};

const ARRAY_REGEX = /^(.*)\[([0-9]*?)]$/;
const BYTES_REGEX = /^bytes([0-9]{1,2})$/;
const NUMBER_REGEX = /^u?int([0-9]*)?$/;

function buildValue(
  data: TypedData,
  hasher: HashGenerator,
  value: any,
  type: string,
): Value {
  if (type in data.types) {
    return {
      type: "Struct",
      value: buildStruct(data, hasher, value, type),
    };
  }

  const array_match = type.match(ARRAY_REGEX);
  if (array_match) {
    const itemType = array_match[1];
    const length = Number(array_match[2]);

    if (!Array.isArray(value)) {
      throw new Error(`Array is required but ${value} is not an array!`);
    }
    if (!Number.isNaN(length) && value.length !== length) {
      throw new Error(
        `Expected array length: ${length}, actual length: ${value.length}`,
      );
    }

    return {
      type: "Array",
      value: value.map((item) =>
        top_level.Value.pack(buildValue(data, hasher, item, itemType)),
      ),
    };
  }

  switch (type) {
    case "bool":
      {
        return {
          type: "Bool",
          value: !!value,
        };
      }
      break;
    case "bytes":
      {
        return {
          type: "Bytes",
          value: bytes.bytify(value),
        };
      }
      break;
    case "string":
      {
        return {
          type: "String",
          value: new TextEncoder().encode(value),
        };
      }
      break;
    case "address":
      {
        const address = bytes.bytify(value);
        if (address.byteLength !== 20) {
          throw new Error(`Invalid address: ${value}`!);
        }
        return {
          type: "Address",
          value: address,
        };
      }
      break;
  }

  const bytesMatch = type.match(BYTES_REGEX);
  if (bytesMatch) {
    const length = Number(bytesMatch[1]);
    if (Number.isNaN(length) || length <= 0 || length > 32) {
      throw new Error(`${type} is not a valid fixed-bytes type!`);
    }
    const data = bytes.bytify(value);
    if (data.byteLength != length) {
      throw new Error(
        `Type ${type} cannot store bytes of length ${data.byteLength}`,
      );
    }
    return {
      type: "FixedBytes",
      value: data,
    };
  }

  const numberMatch = type.match(NUMBER_REGEX);
  if (numberMatch) {
    const signed = !type.startsWith("u");
    const bits = Number(numberMatch[1]);
    if (Number.isNaN(bits) || bits < 8 || bits > 256 || bits % 8 !== 0) {
      throw new Error(`${type} is not a valid number type!`);
    }

    let v = toJSBI(value);
    let min = JSBI.BigInt(0);
    // 2 ** bits - 1
    let max = JSBI.subtract(
      JSBI.leftShift(JSBI.BigInt(1), JSBI.BigInt(bits)),
      JSBI.BigInt(1),
    );
    let unionType = "Uint";
    if (signed) {
      // - 2 ** (bits - 1)
      min = JSBI.subtract(
        JSBI.BigInt(0),
        JSBI.leftShift(JSBI.BigInt(1), JSBI.BigInt(bits - 1)),
      );
      // 2 ** (bits - 1) - 1
      max = JSBI.subtract(
        JSBI.leftShift(JSBI.BigInt(1), JSBI.BigInt(bits - 1)),
        JSBI.BigInt(1),
      );
      unionType = "Int";
    }
    if (JSBI.lessThan(v, min) || JSBI.greaterThan(v, max)) {
      throw new Error(
        `Value must be between ${min.toString()} and ${max.toString()}, but got ${v.toString()}`,
      );
    }

    const buffer = new Uint8Array(bits / 8);
    for (let i = 0; i < buffer.length; i++) {
      buffer[i] = JSBI.toNumber(JSBI.asUintN(8, v));
      v = JSBI.signedRightShift(v, JSBI.BigInt(8));
    }

    return {
      type: unionType,
      value: buffer.reverse(),
    };
  }

  throw new Error(`Unknown value type: ${type}!`);
}

function parseValue(
  data: TypedData,
  hasher: HashGenerator,
  packed: Value,
  type: string,
): any {
  if (type in data.types) {
    if (packed.type !== "Struct") {
      throw new Error(`Expected Struct union type but found ${packed.type}`);
    }
    return parseStruct(data, hasher, packed.value, type);
  }

  const array_match = type.match(ARRAY_REGEX);
  if (array_match) {
    const itemType = array_match[1];
    const length = Number(array_match[2]);

    if (packed.type !== "Array") {
      throw new Error(`Expected Array union type but found ${packed.type}`);
    }
    if (!Array.isArray(packed.value)) {
      throw new Error(`Array is required but ${packed.value} is not an array!`);
    }
    if (!Number.isNaN(length) && packed.value.length !== length) {
      throw new Error(
        `Expected array length: ${length}, actual length: ${packed.value.length}`,
      );
    }

    return packed.value.map((packedItem) =>
      parseValue(data, hasher, top_level.Value.unpack(packedItem), itemType),
    );
  }

  switch (type) {
    case "bool":
      {
        if (packed.type !== "Bool") {
          throw new Error(`Expected Bool union type but found ${packed.type}`);
        }
        return packed.value;
      }
      break;
    case "bytes":
      {
        if (packed.type !== "Bytes") {
          throw new Error(`Expected Bytes union type but found ${packed.type}`);
        }
        return packed.value;
      }
      break;
    case "string":
      {
        if (packed.type !== "String") {
          throw new Error(
            `Expected String union type but found ${packed.type}`,
          );
        }
        return new TextDecoder().decode(bytes.bytify(packed.value));
      }
      break;
    case "address":
      {
        if (packed.type !== "Address") {
          throw new Error(
            `Expected Address union type but found ${packed.type}`,
          );
        }
        if (bytes.bytify(packed.value).byteLength !== 20) {
          throw new Error("Address must be of 20 bytes!");
        }
        return packed.value;
      }
      break;
  }

  const bytesMatch = type.match(BYTES_REGEX);
  if (bytesMatch) {
    if (packed.type !== "FixedBytes") {
      throw new Error(
        `Expected FixedBytes union type but found ${packed.type}`,
      );
    }

    const length = Number(bytesMatch[1]);
    if (Number.isNaN(length) || length <= 0 || length > 32) {
      throw new Error(`${type} is not a valid fixed-bytes type!`);
    }
    const data = bytes.bytify(packed.value);
    if (data.byteLength != length) {
      throw new Error(
        `Type ${type} cannot store bytes of length ${data.byteLength}`,
      );
    }
    return packed.value;
  }

  const numberMatch = type.match(NUMBER_REGEX);
  if (numberMatch) {
    const signed = !type.startsWith("u");
    const bits = Number(numberMatch[1]);
    if (Number.isNaN(bits) || bits < 8 || bits > 256 || bits % 8 !== 0) {
      throw new Error(`${type} is not a valid number type!`);
    }

    let unionType = "Uint";
    if (signed) {
      unionType = "Int";
    }
    if (packed.type !== unionType) {
      throw new Error(
        `Expected ${unionType} union type but found ${packed.type}`,
      );
    }

    let value = JSBI.BigInt(0);
    for (const byte of bytes.bytify(packed.value)) {
      value = JSBI.add(
        JSBI.leftShift(value, JSBI.BigInt(8)),
        JSBI.BigInt(byte),
      );
    }

    if (signed) {
      value = JSBI.asIntN(bits, value);
    } else {
      value = JSBI.asUintN(bits, value);
    }

    if (bits <= 32) {
      return JSBI.toNumber(value);
    } else {
      return value.toString();
    }
  }

  throw new Error(`Unknown value type: ${type}!`);
}

function buildStruct(
  data: TypedData,
  hasher: HashGenerator,
  value: any,
  type: string,
): Struct {
  if (!(type in data.types)) {
    throw new Error(`${type} is not found in defined types!`);
  }
  const typeHash = hasher.type_hash(data, type);
  const typeDefinition = data.types[type];
  const expectedFields = new Set(typeDefinition.map(({ name }) => name));
  const actualFields = new Set(Object.keys(value));
  if (!isEqual(expectedFields, actualFields)) {
    throw new Error(
      `Invalid struct, expected fields: ${expectedFields}, actual fields: ${actualFields}`,
    );
  }
  const serializedValues = typeDefinition.map(({ name, type }) => {
    return top_level.Value.pack(buildValue(data, hasher, value[name], type));
  });

  return {
    type_hash: typeHash,
    values: serializedValues,
  };
}

function parseStruct(
  data: TypedData,
  hasher: HashGenerator,
  packed: Struct,
  type: string,
): any {
  if (!(type in data.types)) {
    throw new Error(`${type} is not found in defined types!`);
  }
  const expectedTypeHash = hasher.type_hash(data, type);
  if (
    expectedTypeHash.type === "Byte32" &&
    packed.type_hash.type === "Byte32"
  ) {
    if (
      !isEqual(expectedTypeHash.value, bytes.bytify(packed.type_hash.value))
    ) {
      throw new Error(
        `Expected type hash: ${
          expectedTypeHash.value
        }, actual type hash: ${bytes.bytify(packed.type_hash.value)}`,
      );
    }
  }

  const typeDefinition = data.types[type];
  if (typeDefinition.length !== packed.values.length) {
    throw new Error(
      `Expected ${typeDefinition.length} fields, actual ${packed.values.length} fields!`,
    );
  }

  const values: Record<string, any> = {};
  for (let i = 0; i < typeDefinition.length; i++) {
    values[typeDefinition[i].name] = parseValue(
      data,
      hasher,
      top_level.Value.unpack(packed.values[i]),
      typeDefinition[i].type,
    );
  }

  return values;
}
